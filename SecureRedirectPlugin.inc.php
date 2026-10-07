<?php

/**
 * @file plugins/generic/secureRedirect/SecureRedirectPlugin.inc.php
 *
 * Hotfix for CVE-2024-7902: open redirect via /login/signOut?source=
 * on OJS 3.3.x (e.g. ?source=.evil.com => Location: https://victim.evil.com).
 *
 * Strategy: hook into Request::redirect (called by PKPRequest::redirectUrl
 * for EVERY redirect incl. signIn/signOut) and sanitize the URL before the
 * header("Location: ...") is sent. Same idea as the official 3.5.x fix
 * (prefix "/" + strip "@") but enforced centrally so it cannot be bypassed
 * by double-encoding like a WAF rule could.
 *
 * - relative path starting with single slash (/index, /login, ...) => allow
 * - absolute URL => host must match current server host or base_url host
 *   AND path must not start with //, /\ or contain backslash (Chrome
 *   normalizes \ to /, so /\evil is same as //evil)
 * - anything else (subdomain trick .evil.com, userinfo @evil.com,
 *   scheme-relative //evil.com, javascript:/data:, empty) => rewrite to "/"
 */

import('lib.pkp.classes.plugins.GenericPlugin');

class SecureRedirectPlugin extends GenericPlugin {

	/**
	 * @copydoc Plugin::register()
	 */
	function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);
		if (!Config::getVar('general', 'installed') || defined('RUNNING_UPGRADE')) return true;
		if ($success && $this->getEnabled($mainContextId)) {
			HookRegistry::register('Request::redirect', array($this, 'sanitizeRedirect'));
		}
		return $success;
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	function getDisplayName() {
		return 'SecureRedirect Fix (CVE-2024-7902)';
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	function getDescription() {
		return 'Block open redirect in login/signOut?source= without upgrade or WAF. Allows only same-host redirects.';
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 * Site-wide so getEnabled() reads context 0 and the hook is always active.
	 */
	function isSitePlugin() {
		return true;
	}

	/**
	 * Hook callback for Request::redirect. $args[0] is &$url by reference.
	 * Return false = let redirect continue with (possibly rewritten) URL.
	 */
	function sanitizeRedirect($hookName, $args) {
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
		// (mirrors official 3.5.x fix: str_replace('@', '', $source)).
		if (preg_match('#^/[^/\\\\]#', $url)) {
			if (strpos($url, '@') !== false || strpos($url, '\\') !== false) {
				error_log('SecureRedirect blocked @/backslash in path: ' . $url);
				$url = '/';
			}
			return false;
		}
		// Anything relative that is NOT single-slash (/evil is ok,
		// //evil, /\evil, \/evil, .evil are not) => home.
		if (strpos($url, '/') === 0 || strpos($url, '\\') === 0 || strpos($url, '.') === 0 || strpos($url, '@') === 0) {
			error_log('SecureRedirect blocked suspicious relative: ' . $url);
			$url = '/';
			return false;
		}

		// 4. Absolute URL: host must match this server (or base_url host).
		$request = Application::get()->getRequest();
		$allowed = array();
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
		// Browser (Chrome) normalizes backslash to slash, so /\evil.com
		// behaves like //evil.com. Collapse to "/" to stay clean.
		$path = isset($parts['path']) ? $parts['path'] : '';
		// Decode %2f %5c %40 before checking (bypass via /%2Fevil, /%5Cevil).
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
