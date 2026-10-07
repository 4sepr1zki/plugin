<?php

/**
 * @file plugins/generic/secureRedirect/SecureRedirectPlugin.php
 *
 * Hotfix for CVE-2024-7902: open redirect via /login/signOut?source=
 * Compatible with OJS 3.4.x (PSR-4 Namespaces).
 */

namespace APP\plugins\generic\secureRedirect;

use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\config\Config;
use PKP\core\PKPApplication;

class SecureRedirectPlugin extends GenericPlugin {

	/**
	 * @copydoc Plugin::register()
	 */
	public function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);
		if (!Config::getVar('general', 'installed') || defined('RUNNING_UPGRADE')) return true;
		if ($success && $this->getEnabled($mainContextId)) {
			Hook::add('Request::redirect', [$this, 'sanitizeRedirect']);
		}
		return $success;
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	public function getDisplayName() {
		return 'SecureRedirect Fix (CVE-2024-7902)';
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	public function getDescription() {
		return 'Block open redirect in login/signOut?source= without upgrade or WAF. Allows only same-host redirects.';
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 */
	public function isSitePlugin() {
		return true;
	}

	/**
	 * Hook callback for Request::redirect. $args[0] is &$url by reference.
	 * Return false = let redirect continue with (possibly rewritten) URL.
	 */
	public function sanitizeRedirect($hookName, $args) {
		$url =& $args[0];
		$url = trim((string) $url);

		// 1. Empty => home.
		if ($url === '' || $url === null) {
			$url = '/';
			return false;
		}

		// 2. Dangerous scheme (javascript:, data:, vbscript:) => home.
		if (preg_match('/^\s*(javascript|data|vbscript)\s*:/i', $url)) {
			error_log('SecureRedirect blocked dangerous scheme: ' . $url);
			$url = '/';
			return false;
		}

		// 3. Relative URL with single leading slash (/index, /Edukasi/...)
		// is safe. Reject //evil.com, /\evil, \/ tricks, and any @ in path
		if (preg_match('#^/[^/\\\\]#', $url)) {
			if (strpos($url, '@') !== false || strpos($url, '\\') !== false) {
				error_log('SecureRedirect blocked @/backslash in path: ' . $url);
				$url = '/';
			}
			return false;
		}
		// Anything relative that is NOT single-slash (/evil is ok, //evil, /\evil, .evil are not)
		if (strpos($url, '/') === 0 || strpos($url, '\\') === 0 || strpos($url, '.') === 0 || strpos($url, '@') === 0) {
			error_log('SecureRedirect blocked suspicious relative: ' . $url);
			$url = '/';
			return false;
		}

		// 4. Absolute URL: host must match this server (or base_url host).
		$request = PKPApplication::get()->getRequest();
		$allowed = [];
		$serverHost = strtolower($request->getServerHost(false));
		if ($serverHost !== '') $allowed[] = preg_replace('/^www\./', '', $serverHost);
		$baseUrl = Config::getVar('general', 'base_url');
		if (!empty($baseUrl)) {
			$baseParts = @parse_url($baseUrl);
			if (!empty($baseParts['host'])) {
				$allowed[] = preg_replace('/^www\./', '', strtolower($baseParts['host']));
			}
		}

		$parts = @parse_url($url);
		if ($parts === false || empty($parts['host'])) {
			error_log('SecureRedirect blocked unparseable/relative: ' . $url);
			$url = '/';
			return false;
		}

		$host = preg_replace('/^www\./', '', strtolower($parts['host']));
		$hostAllowed = false;
		foreach ($allowed as $a) {
			$a = preg_replace('/^www\./', '', strtolower(trim($a)));
			if ($a !== '' && $host === $a) {
				$hostAllowed = true;
				break;
			}
		}
		if (!$hostAllowed) {
			error_log('SecureRedirect blocked off-host redirect: ' . $url);
			$url = '/';
			return false;
		}

		// 5. Same host but suspicious path: //evil, /\evil, \evil, @ in path.
		$path = isset($parts['path']) ? $parts['path'] : '';
		$decodedPath = strtolower(rawurldecode($path));
		if (preg_match('#^/[/\\\\]#', $path) || preg_match('#^/[/\\\\]#', $decodedPath)
			|| strpos($path, '\\') !== false || strpos($decodedPath, '\\') !== false
			|| strpos($url, '@') !== false) {
			error_log('SecureRedirect blocked suspicious same-host path: ' . $url);
			$url = '/';
			return false;
		}

		return false; // same host + clean path => allow
	}
}
