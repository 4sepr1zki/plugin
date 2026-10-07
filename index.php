<?php

/**
 * @file plugins/generic/secureRedirect/index.php
 *
 * Copyright (c) 2026
 * Distributed under the GNU GPL v3.
 *
 * @ingroup plugins_generic_secureRedirect
 * @brief Universal Hybrid Wrapper for SecureRedirect plugin (Supports OJS 3.2, 3.3, and 3.4).
 */

if (class_exists('\PKP\plugins\GenericPlugin')) {
	// OJS 3.4+ (PSR-4 Namespaced)
	require_once(__DIR__ . '/SecureRedirectPlugin.php');
	return new \APP\plugins\generic\secureRedirect\SecureRedirectPlugin();
} else {
	// OJS 3.2 & 3.3 (Legacy Loader)
	require_once(__DIR__ . '/SecureRedirectPlugin.inc.php');
	return new SecureRedirectPlugin();
}
