<?php

namespace APP\plugins\generic\ojsSecurityHardener;

use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\config\Config;

require_once __DIR__ . '/classes/SecurityHardenerCore.php';

/**
 * @file plugins/generic/ojsSecurityHardener/OjsSecurityHardenerPlugin.php
 *
 * Copyright (c) 2026
 * Distributed under the GNU GPL v3.
 *
 * @class OjsSecurityHardenerPlugin
 * @ingroup plugins_generic_ojsSecurityHardener
 *
 * @brief Enterprise Virtual Security Patch & Monitoring Suite for OJS (OJS 3.4+).
 */
class OjsSecurityHardenerPlugin extends GenericPlugin {

	/** @var \SecurityHardenerCore */
	protected $core = null;

	/**
	 * @copydoc Plugin::register()
	 */
	public function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);
		$this->core = \SecurityHardenerCore::getInstance($this);

		if (!Config::getVar('general', 'installed') || defined('RUNNING_UPGRADE')) return true;

		// Intercept Secret Security Dashboard Request early
		$this->core->handleDashboardRequest();

		if ($success && $this->getEnabled($mainContextId)) {
			// Virtual Patch CVE-2024-7902 & CVE-2024-46326 (Open Redirect)
			Hook::add('Request::redirect', [$this->core, 'sanitizeRedirect']);

			// Virtual Patch CVE-2022-24181 (Host Header XSS / Poisoning)
			Hook::add('Request::getServerHost', [$this->core, 'sanitizeServerHost']);

			// Virtual Patch CVE-2026-19906 (API Key CSPRNG)
			Hook::add('APIProfileForm::execute', [$this->core, 'hardenApiKeyGeneration']);

			// Bulletproof Early Login Interception & Active Lockout check
			Hook::add('Dispatcher::dispatch', [$this->core, 'interceptLoginAttempts']);

			// Real Virtual Patch CVE-2024-56525 & Uploaded XML XXE Scanner
			Hook::add('Dispatcher::dispatch', [$this->core, 'inspectUploadedFiles']);

			// Core Authentication Hooks
			Hook::add('User::login', [$this->core, 'handleSuccessfulLogin']);
			Hook::add('User::loginFailed', [$this->core, 'handleFailedLoginHook']);

			// UI Notice on Login & Register Pages & Global Security Headers
			Hook::add('TemplateManager::display', [$this->core, 'injectUiAndHeaders']);

			// Password Minimum Length & Complexity Policy on Registration
			Hook::add('registrationform::validate', [$this->core, 'validateRegistrationPassword']);
			Hook::add('pkpregistrationform::validate', [$this->core, 'validateRegistrationPassword']);
		}

		return $success;
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	public function getDisplayName() {
		return __('plugins.generic.ojsSecurityHardener.displayName', [], 'OJS Security Hardener & Monitoring Dashboard');
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	public function getDescription() {
		return __('plugins.generic.ojsSecurityHardener.description', [], 'Enterprise virtual patch suite with Anti Brute-force, Secret Monitoring Dashboard, Dedicated Audit Logger, and CVE mitigations.');
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 */
	public function isSitePlugin() {
		return true;
	}

	/**
	 * Forwarding helper
	 */
	public function getCore() {
		if ($this->core === null) {
			$this->core = \SecurityHardenerCore::getInstance($this);
		}
		return $this->core;
	}
}
