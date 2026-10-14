<?php

/**
 * @file plugins/generic/ojsSecurityHardener/index.php
 *
 * Copyright (c) 2026
 * Distributed under the GNU GPL v3.
 *
 * @ingroup plugins_generic_ojsSecurityHardener
 * @brief Universal Hybrid Wrapper for OjsSecurityHardener plugin.
 * Compatible across OJS 2.4.x, 3.0.x - 3.3.x (Legacy Loader) and OJS 3.4.x+ (PSR-4 Namespaced).
 */

if (class_exists('\PKP\plugins\GenericPlugin')) {
	// OJS 3.4+ (PSR-4 Namespaced)
	require_once(__DIR__ . '/OjsSecurityHardenerPlugin.php');
	return new \APP\plugins\generic\ojsSecurityHardener\OjsSecurityHardenerPlugin();
} else {
	// OJS 2.4.x, 3.0.x, 3.1.x, 3.2.x, 3.3.x (Legacy Loader)
	require_once(__DIR__ . '/OjsSecurityHardenerPlugin.inc.php');
	return new OjsSecurityHardenerPlugin();
}
