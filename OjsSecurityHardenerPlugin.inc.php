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
 * @brief Enterprise Virtual Security Patch & Monitoring Suite for OJS (OJS 2.4.x - 3.3.x).
 */

if (!class_exists('GenericPlugin')) {
	if (function_exists('import')) {
		import('lib.pkp.classes.plugins.GenericPlugin');
		if (!class_exists('GenericPlugin')) {
			import('classes.plugins.GenericPlugin');
		}
	}
}

require_once __DIR__ . '/classes/SecurityHardenerCore.php';

class OjsSecurityHardenerPlugin extends GenericPlugin {

	/** @var SecurityHardenerCore */
	protected $core = null;

	/**
	 * @copydoc Plugin::register()
	 */
	function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);
		$this->core = SecurityHardenerCore::getInstance($this);

		// Check installation status in OJS safely
		$installed = true;
		if (class_exists('Config')) {
			$installed = Config::getVar('general', 'installed');
		}
		if (!$installed || defined('RUNNING_UPGRADE')) return true;

		// Intercept Secret Security Dashboard Request early
		$this->core->handleDashboardRequest();

		if ($success) {
			$enabled = false;
			if (method_exists($this, 'getEnabled')) {
				$enabled = $this->getEnabled($mainContextId);
			} else {
				$enabled = true;
			}

			if ($enabled && class_exists('HookRegistry')) {
				// Virtual Patch CVE-2024-7902 & CVE-2024-46326 (Open Redirect)
				HookRegistry::register('Request::redirect', array($this->core, 'sanitizeRedirect'));

				// Virtual Patch CVE-2022-24181 (Host Header XSS / Poisoning)
				HookRegistry::register('Request::getServerHost', array($this->core, 'sanitizeServerHost'));

				// Virtual Patch CVE-2026-19906 (API Key CSPRNG)
				HookRegistry::register('APIProfileForm::execute', array($this->core, 'hardenApiKeyGeneration'));

				// Bulletproof Early Login Interception & Active Lockout check
				HookRegistry::register('Dispatcher::dispatch', array($this->core, 'interceptLoginAttempts'));

				// Real Virtual Patch CVE-2024-56525 & Uploaded XML XXE Scanner
				HookRegistry::register('Dispatcher::dispatch', array($this->core, 'inspectUploadedFiles'));

				// Core Authentication Hooks
				HookRegistry::register('User::login', array($this->core, 'handleSuccessfulLogin'));
				HookRegistry::register('User::loginFailed', array($this->core, 'handleFailedLoginHook'));

				// UI Notice on Login & Register Pages & Global Security Headers
				HookRegistry::register('TemplateManager::display', array($this->core, 'injectUiAndHeaders'));

				// Password Minimum Length & Complexity Policy on Registration
				HookRegistry::register('registrationform::validate', array($this->core, 'validateRegistrationPassword'));
				HookRegistry::register('pkpregistrationform::validate', array($this->core, 'validateRegistrationPassword'));
			}
		}

		return $success;
	}

	/**
	 * @copydoc Plugin::getDisplayName()
	 */
	function getDisplayName() {
		return __('plugins.generic.ojsSecurityHardener.displayName', array(), 'OJS Security Hardener & Monitoring Dashboard');
	}

	/**
	 * @copydoc Plugin::getDescription()
	 */
	function getDescription() {
		return __('plugins.generic.ojsSecurityHardener.description', array(), 'Enterprise virtual patch suite with Anti Brute-force, Secret Monitoring Dashboard, Dedicated Audit Logger, and CVE mitigations.');
	}

	/**
	 * @copydoc Plugin::isSitePlugin()
	 */
	function isSitePlugin() {
		return true;
	}

	/**
	 * Forwarding helper for legacy callers
	 */
	function getCore() {
		if ($this->core === null) {
			$this->core = SecurityHardenerCore::getInstance($this);
		}
		return $this->core;
	}

	/**
	 * Backward compatibility proxy for test suite and legacy code
	 */
	function __call($name, $arguments) {
		$core = $this->getCore();
		if (method_exists($core, $name)) {
			return call_user_func_array(array($core, $name), $arguments);
		}
		trigger_error("Call to undefined method " . get_class($this) . "::$name()", E_USER_ERROR);
	}
}
