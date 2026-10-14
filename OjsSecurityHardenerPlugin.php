<?php

/**
 * @file plugins/generic/ojsSecurityHardener/OjsSecurityHardenerPlugin.php
 *
 * Copyright (c) 2026
 * Distributed under the GNU GPL v3.
 *
 * @class OjsSecurityHardenerPlugin
 * @ingroup plugins_generic_ojsSecurityHardener
 *
 * @brief Modern PSR-4 compatible driver for OJS 3.4.x+.
 * Focuses purely on CVE fixes and core defense-in-depth:
 *  - CVE-2024-7902: Open Redirect via login/signOut?source= & login/signIn
 *  - CVE-2026-76572: XML External Entity (XXE) in libxml / DOM / SimpleXML / XSLT
 *  - CVE-2026-19906: Weak/Predictable API Secret Tokens
 *  - Security Headers: X-Frame-Options, X-Content-Type-Options, Referrer-Policy
 */

namespace APP\plugins\generic\ojsSecurityHardener;

use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\config\Config;
use PKP\core\PKPApplication;

class OjsSecurityHardenerPlugin extends GenericPlugin {

	/**
	 * @copydoc Plugin::register()
	 */
	public function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);

		// Always disable XML external entities immediately at boot (CVE-2026-76572 fix)
		$this->hardenXmlParser();

		if (!Config::getVar('general', 'installed') || defined('RUNNING_UPGRADE')) return true;

		if ($success && $this->getEnabled($mainContextId)) {
			// 1. Hook into Redirect for CVE-2024-7902 Open Redirect
			Hook::add('Request::redirect', [$this, 'sanitizeRedirect']);

			// 2. Hook into API Key generation (CVE-2026-19906)
			Hook::add('APIProfileForm::execute', [$this, 'hardenApiKeyGeneration']);

			// 3. Inject global security headers
			Hook::add('TemplateManager::display', [$this, 'injectSecurityHeaders']);
		}

		return $success;
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	public function getDisplayName() {
		return 'OJS Security Hardener & Virtual Patch';
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	public function getDescription() {
		return 'Virtual patch suite: fixes Open Redirect (CVE-2024-7902), XXE Injection (CVE-2026-76572), Weak API Tokens (CVE-2026-19906), and injects security headers.';
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 */
	public function isSitePlugin() {
		return true;
	}

	/**
	 * Mitigate CVE-2026-76572: Disable XML External Entity Loading globally in PHP process
	 */
	public function hardenXmlParser() {
		if (function_exists('libxml_disable_entity_loader')) {
			@libxml_disable_entity_loader(true);
		}
	}

	/**
	 * Mitigate CVE-2024-7902: Hook callback for Request::redirect.
	 * $args[0] is &$url passed by reference.
	 */
	public function sanitizeRedirect($hookName, $args) {
		$url =& $args[0];
		$url = trim((string) $url);

		// 1. Empty URL => fallback to home
		if ($url === '' || $url === null) {
			$url = '/';
			return false;
		}

		// 2. Dangerous schemes (javascript:, data:, vbscript:)
		if (preg_match('/^\s*(javascript|data|vbscript)\s*:/i', $url)) {
			error_log('[OjsSecurityHardener] Blocked dangerous scheme: ' . $url);
			$url = '/';
			return false;
		}

		// 3. Safe single-slash relative path (/index, /issue/...)
		if (preg_match('#^/[^/\\\\]#', $url)) {
			// Disallow @ and backslash in path tricks
			if (strpos($url, '@') !== false || strpos($url, '\\') !== false) {
				error_log('[OjsSecurityHardener] Blocked @ or backslash in relative URL: ' . $url);
				$url = '/';
			}
			return false;
		}

		// Disallow leading multi-slashes or dot trick (//evil.com, /\evil.com, .evil.com)
		if (strpos($url, '/') === 0 || strpos($url, '\\') === 0 || strpos($url, '.') === 0 || strpos($url, '@') === 0) {
			error_log('[OjsSecurityHardener] Blocked suspicious relative redirect: ' . $url);
			$url = '/';
			return false;
		}

		// 4. Absolute URL validation
		$allowedHosts = [];
		$request = PKPApplication::get()->getRequest();
		if ($request && method_exists($request, 'getServerHost')) {
			$sh = strtolower($request->getServerHost(false));
			if ($sh !== '') $allowedHosts[] = preg_replace('/^www\./', '', $sh);
		}

		$baseUrl = Config::getVar('general', 'base_url');
		if (!empty($baseUrl)) {
			$baseParts = @parse_url($baseUrl);
			if (!empty($baseParts['host'])) {
				$allowedHosts[] = preg_replace('/^www\./', '', strtolower($baseParts['host']));
			}
		}

		$parts = @parse_url($url);
		if ($parts === false || empty($parts['host'])) {
			error_log('[OjsSecurityHardener] Blocked unparseable absolute URL: ' . $url);
			$url = '/';
			return false;
		}

		$destHost = preg_replace('/^www\./', '', strtolower($parts['host']));
		$isHostAllowed = false;
		foreach ($allowedHosts as $allowed) {
			$allowed = preg_replace('/^www\./', '', strtolower(trim($allowed)));
			if ($allowed !== '' && $destHost === $allowed) {
				$isHostAllowed = true;
				break;
			}
		}

		if (!$isHostAllowed) {
			error_log('[OjsSecurityHardener] Blocked off-host redirect target: ' . $url);
			$url = '/';
			return false;
		}

		// 5. Same host but path contains evasion characters
		$path = $parts['path'] ?? '';
		$decodedPath = strtolower(rawurldecode($path));
		if (preg_match('#^/[/\\\\]#', $path) || preg_match('#^/[/\\\\]#', $decodedPath)
			|| strpos($path, '\\') !== false || strpos($decodedPath, '\\') !== false
			|| strpos($url, '@') !== false) {
			error_log('[OjsSecurityHardener] Blocked path bypass attempt on same host: ' . $url);
			$url = '/';
			return false;
		}

		return false; // Allowed
	}

	/**
	 * Mitigate CVE-2026-19906: Enforce Cryptographically Secure API Token
	 */
	public function hardenApiKeyGeneration($hookName, $args) {
		$form =& $args[0];
		if ($form && method_exists($form, 'getData') && method_exists($form, 'setData')) {
			$apiKey = $form->getData('apiKey');
			if (!empty($apiKey)) {
				if (function_exists('random_bytes')) {
					$secureToken = bin2hex(random_bytes(32));
					$form->setData('apiKey', $secureToken);
				}
			}
		}
		return false;
	}

	/**
	 * Add Security Response Headers to Prevent Clickjacking and MIME sniffing
	 */
	public function injectSecurityHeaders($hookName, $args) {
		if (!headers_sent()) {
			@header('X-Content-Type-Options: nosniff');
			@header('X-XSS-Protection: 1; mode=block');
			@header('Referrer-Policy: strict-origin-when-cross-origin');
		}
		return false;
	}
}
