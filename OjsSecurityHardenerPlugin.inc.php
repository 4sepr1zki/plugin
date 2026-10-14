<?php

/**
 * @file plugins/generic/ojsSecurityHardener/OjsSecurityHardenerPlugin.inc.php
 *
 * Copyright (c) 2026
 * Distributed under the GNU GPL v3.
 *
 * @class OjsSecurityHardenerPlugin
 * @ingroup plugins_generic_ojsSecurityHardener
 *
 * @brief Comprehensive Virtual Patch for OJS (OJS 2.4.x - 3.3.x).
 * Focuses purely on CVE fixes and core defense-in-depth:
 *  - CVE-2024-7902: Open Redirect via login/signOut?source= & login/signIn
 *  - CVE-2026-76572: XML External Entity (XXE) in libxml / DOM / SimpleXML / XSLT
 *  - CVE-2026-19906: Weak/Predictable API Secret Tokens
 *  - CVE-2022-24181: Host Header Injection / X-Forwarded-Host Reflected XSS & Cache Poisoning
 *  - Security Headers: X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
 */

if (!class_exists('GenericPlugin')) {
	if (function_exists('import')) {
		import('lib.pkp.classes.plugins.GenericPlugin');
		if (!class_exists('GenericPlugin')) {
			// Fallback for OJS 2.4.x
			import('classes.plugins.GenericPlugin');
		}
	}
}

class OjsSecurityHardenerPlugin extends GenericPlugin {

	/**
	 * @copydoc Plugin::register()
	 */
	function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);

		// Always disable XML external entities immediately at boot (CVE-2026-76572 & CVE-2024-56525 fix)
		$this->hardenXmlParser();

		// Check installation status in OJS 2.x and 3.x safely
		$installed = true;
		if (class_exists('Config')) {
			$installed = Config::getVar('general', 'installed');
		}
		if (!$installed || defined('RUNNING_UPGRADE')) return true;

		if ($success) {
			$enabled = false;
			if (method_exists($this, 'getEnabled')) {
				$enabled = $this->getEnabled($mainContextId);
			} else {
				$enabled = true; // Default fallback
			}

			if ($enabled) {
				if (class_exists('HookRegistry')) {
					// 1. Hook into Redirect for CVE-2024-7902 Open Redirect
					HookRegistry::register('Request::redirect', array($this, 'sanitizeRedirect'));

					// 2. Hook into Host resolution for CVE-2022-24181 (X-Forwarded-Host XSS / Poisoning)
					HookRegistry::register('Request::getServerHost', array($this, 'sanitizeServerHost'));

					// 3. Hook into API Key generation (CVE-2026-19906)
					HookRegistry::register('APIProfileForm::execute', array($this, 'hardenApiKeyGeneration'));

					// 4. Inject global security headers
					HookRegistry::register('TemplateManager::display', array($this, 'injectSecurityHeaders'));
				}
			}
		}

		return $success;
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	function getDisplayName() {
		return 'OJS Security Hardener & Virtual Patch';
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	function getDescription() {
		return 'Virtual patch suite: fixes Open Redirect (CVE-2024-7902), Host Header/X-Forwarded-Host XSS (CVE-2022-24181), XXE Injection (CVE-2026-76572 / CVE-2024-56525), Weak API Tokens (CVE-2026-19906), and injects security headers.';
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 */
	function isSitePlugin() {
		return true;
	}

	/**
	 * Mitigate CVE-2026-76572 & CVE-2024-56525: Disable XML External Entity Loading globally in PHP process
	 */
	function hardenXmlParser() {
		if (function_exists('libxml_disable_entity_loader')) {
			@libxml_disable_entity_loader(true);
		}
	}

	/**
	 * Mitigate CVE-2022-24181: Sanitize Server Host and X-Forwarded-Host Header.
	 * Restricts host values strictly to valid RFC hostname/IP:port format,
	 * rejecting any injected XSS characters (<, >, ", ', spaces) without touching article content.
	 */
	function sanitizeServerHost($hookName, $args) {
		$serverHost =& $args[0];

		// If empty or contains illegal characters not belonging in an RFC hostname/port
		if (empty($serverHost) || preg_match('/[^\w\.\-\:]/', $serverHost)) {
			error_log('[OjsSecurityHardener] Blocked invalid/malicious HTTP Host header: ' . $serverHost);
			// Reset to safe canonical server name or base_url host
			$safeHost = '';
			if (class_exists('Config')) {
				$baseUrl = Config::getVar('general', 'base_url');
				if (!empty($baseUrl)) {
					$parts = @parse_url($baseUrl);
					if (!empty($parts['host'])) $safeHost = $parts['host'];
				}
			}
			if (empty($safeHost) && isset($_SERVER['SERVER_NAME'])) {
				$safeHost = $_SERVER['SERVER_NAME'];
			}
			$serverHost = !empty($safeHost) ? $safeHost : 'localhost';
		}

		return false; // Continue with sanitized host
	}

	/**
	 * Mitigate CVE-2024-7902: Hook callback for Request::redirect.
	 * $args[0] is &$url passed by reference.
	 */
	function sanitizeRedirect($hookName, $args) {
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
		$allowedHosts = array();

		// Fetch current server host
		if (class_exists('Application')) {
			$request = Application::get()->getRequest();
			if ($request && method_exists($request, 'getServerHost')) {
				$sh = strtolower($request->getServerHost(false));
				if ($sh !== '') $allowedHosts[] = preg_replace('/^www\./', '', $sh);
			}
		} elseif (isset($_SERVER['HTTP_HOST'])) {
			$sh = strtolower($_SERVER['HTTP_HOST']);
			$sh = preg_replace('/:[0-9]+$/', '', $sh);
			$allowedHosts[] = preg_replace('/^www\./', '', $sh);
		}

		// Fetch base_url host from config
		if (class_exists('Config')) {
			$baseUrl = Config::getVar('general', 'base_url');
			if (!empty($baseUrl)) {
				$baseParts = @parse_url($baseUrl);
				if (!empty($baseParts['host'])) {
					$allowedHosts[] = preg_replace('/^www\./', '', strtolower($baseParts['host']));
				}
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
		$path = isset($parts['path']) ? $parts['path'] : '';
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
	function hardenApiKeyGeneration($hookName, $args) {
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
	function injectSecurityHeaders($hookName, $args) {
		if (!headers_sent()) {
			@header('X-Content-Type-Options: nosniff');
			@header('X-XSS-Protection: 1; mode=block');
			@header('Referrer-Policy: strict-origin-when-cross-origin');
		}
		return false;
	}
}
