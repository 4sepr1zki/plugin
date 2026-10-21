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
 * @brief Modern PSR-4 Enterprise Virtual Security Patch & Monitoring Suite for OJS 3.4.x+.
 */

namespace APP\plugins\generic\ojsSecurityHardener;

use PKP\plugins\GenericPlugin;
use PKP\plugins\Hook;
use PKP\config\Config;
use PKP\core\PKPApplication;
use PKP\security\Role;

class OjsSecurityHardenerPlugin extends GenericPlugin {

	public function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);

		// 1. Boot-level XXE Hardening
		$this->hardenXmlParser();

		if (!Config::getVar('general', 'installed') || defined('RUNNING_UPGRADE')) return true;

		// 2. Intercept Secret Security Dashboard Request
		$this->handleDashboardRequest();

		if ($success && $this->getEnabled($mainContextId)) {
			// Virtual Patch CVE-2024-7902 (Open Redirect)
			Hook::add('Request::redirect', [$this, 'sanitizeRedirect']);

			// Virtual Patch CVE-2022-24181 (Host Header XSS & Poisoning)
			Hook::add('Request::getServerHost', [$this, 'sanitizeServerHost']);

			// Virtual Patch CVE-2026-19906 (API Key CSPRNG)
			Hook::add('APIProfileForm::execute', [$this, 'hardenApiKeyGeneration']);

			// Anti Brute-Force & Early Lockout Interception
			Hook::add('Dispatcher::dispatch', [$this, 'interceptLoginAttempts']);

			// Real Virtual Patch CVE-2024-56525 & Uploaded XML XXE Scanner
			Hook::add('Dispatcher::dispatch', [$this, 'inspectUploadedFiles']);

			// Core Authentication Hooks
			Hook::add('User::login', [$this, 'handleSuccessfulLogin']);
			Hook::add('User::loginFailed', [$this, 'handleFailedLoginHook']);

			// UI Notice & Security Headers
			Hook::add('TemplateManager::display', [$this, 'injectUiAndHeaders']);
		}

		return $success;
	}

	public function getDisplayName() {
		return __('plugins.generic.ojsSecurityHardener.displayName', [], 'OJS Security Hardener & Monitoring Dashboard');
	}

	public function getDescription() {
		return __('plugins.generic.ojsSecurityHardener.description', [], 'Enterprise virtual patch suite with Anti Brute-force, Secret Monitoring Dashboard, Dedicated Audit Logger, and CVE mitigations.');
	}

	public function isSitePlugin() {
		return true;
	}

	/**
	 * Mitigate legacy XXE: Disable XML external entity loader where applicable.
	 */
	public function hardenXmlParser() {
		if (PHP_VERSION_ID < 80000 && function_exists('libxml_disable_entity_loader')) {
			@libxml_disable_entity_loader(true);
		}
	}

	/**
	 * Real Virtual Patch for CVE-2024-56525 (User XML Privilege Escalation) & Generic XXE in uploads.
	 */
	public function inspectUploadedFiles($hookName = null, $args = null) {
		if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_FILES)) {
			return false;
		}

		foreach ($_FILES as $file) {
			$tmpNames = is_array($file['tmp_name']) ? $file['tmp_name'] : [$file['tmp_name']];
			$names = is_array($file['name']) ? $file['name'] : [$file['name']];

			foreach ($tmpNames as $idx => $path) {
				if (empty($path) || !is_uploaded_file($path)) continue;
				$filename = strtolower($names[$idx] ?? '');

				// Only scan XML files
				if (substr($filename, -4) === '.xml' || substr($filename, -5) === '.xmls') {
					$content = @file_get_contents($path, false, null, 0, 1024 * 512);
					if ($content === false) continue;

					// 1. Generic XXE Protection: detect dangerous DTD / external entities
					if (preg_match('/<!ENTITY\s+[^>]+(SYSTEM|PUBLIC)\s+[\'"]/i', $content)) {
						$this->logSecurityEvent('XXE_ATTACK', 'Blocked uploaded XML containing external entity declaration: ' . $filename, 'BLOCKED');
						header('HTTP/1.1 403 Forbidden');
						header('Content-Type: text/plain; charset=UTF-8');
						die('Security Alert: Malicious XML External Entity (XXE) detected.');
					}

					// 2. CVE-2024-56525: User XML Privilege Escalation (Super Admin Role Injection)
					if (preg_match('/(ROLE_ID_SITE_ADMIN|<role_id\s+type=[\'"]super_admin[\'"]|<user_group_ref[^>]*>Site Administrator<\/user_group_ref>)/i', $content)) {
						$isSiteAdmin = false;
						$request = PKPApplication::get()->getRequest();
						$user = $request ? $request->getUser() : null;
						if ($user && method_exists($user, 'hasRole')) {
							$isSiteAdmin = $user->hasRole([Role::ROLE_ID_SITE_ADMIN], 0);
						}

						if (!$isSiteAdmin) {
							$this->logSecurityEvent('CVE_2024_56525_BLOCKED', 'Blocked non-site admin attempting to import XML with Site Administrator privileges: ' . $filename, 'CRITICAL');
							header('HTTP/1.1 403 Forbidden');
							header('Content-Type: text/plain; charset=UTF-8');
							die('Security Alert: Privilege escalation detected (CVE-2024-56525). Non-site administrators cannot import users with Site Administrator privileges.');
						}
					}
				}
			}
		}

		return false;
	}

	/**
	 * Mitigate CVE-2022-24181: Sanitize Server Host and X-Forwarded-Host Header.
	 */
	public function sanitizeServerHost($hookName, $args) {
		$serverHost =& $args[0];
		if (empty($serverHost) || preg_match('/[^\w\.\-\:]/', $serverHost)) {
			$this->logSecurityEvent('HOST_INJECTION', 'Blocked malicious HTTP Host: ' . $serverHost, 'BLOCKED');
			$safeHost = '';
			$baseUrl = Config::getVar('general', 'base_url');
			if (!empty($baseUrl)) {
				$parts = @parse_url($baseUrl);
				if (!empty($parts['host'])) $safeHost = $parts['host'];
			}
			if (empty($safeHost) && isset($_SERVER['SERVER_NAME'])) {
				$safeHost = $_SERVER['SERVER_NAME'];
			}
			$serverHost = !empty($safeHost) ? $safeHost : 'localhost';
		}
		return false;
	}

	/**
	 * Mitigate CVE-2024-7902: Sanitize URL before sending HTTP Location header.
	 */
	public function sanitizeRedirect($hookName, $args) {
		$url =& $args[0];
		$url = trim((string) $url);

		if ($url === '' || $url === null) {
			$url = '/';
			return false;
		}

		if (preg_match('/^\s*(javascript|data|vbscript)\s*:/i', $url)) {
			$this->logSecurityEvent('OPEN_REDIRECT', 'Blocked dangerous scheme URL: ' . $url, 'BLOCKED');
			$url = '/';
			return false;
		}

		if (preg_match('#^/[^/\\\\]#', $url)) {
			if (strpos($url, '@') !== false || strpos($url, '\\') !== false) {
				$this->logSecurityEvent('OPEN_REDIRECT', 'Blocked evasion character in relative URL: ' . $url, 'BLOCKED');
				$url = '/';
			}
			return false;
		}

		if (strpos($url, '/') === 0 || strpos($url, '\\') === 0 || strpos($url, '.') === 0 || strpos($url, '@') === 0) {
			$this->logSecurityEvent('OPEN_REDIRECT', 'Blocked suspicious relative redirect: ' . $url, 'BLOCKED');
			$url = '/';
			return false;
		}

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
			$this->logSecurityEvent('OPEN_REDIRECT', 'Blocked unparseable absolute URL: ' . $url, 'BLOCKED');
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
			$this->logSecurityEvent('OPEN_REDIRECT', 'Blocked off-host redirect target: ' . $url, 'BLOCKED');
			$url = '/';
			return false;
		}

		return false;
	}

	/**
	 * Mitigate CVE-2026-19906: Enforce CSPRNG for API Key Generation.
	 */
	public function hardenApiKeyGeneration($hookName, $args) {
		$form =& $args[0];
		if ($form && method_exists($form, 'getData') && method_exists($form, 'setData')) {
			$apiKey = $form->getData('apiKey');
			if (!empty($apiKey)) {
				if (function_exists('random_bytes')) {
					$secureToken = bin2hex(random_bytes(32));
					$form->setData('apiKey', $secureToken);
					$this->logSecurityEvent('API_TOKEN', 'Regenerated API token using CSPRNG random_bytes', 'SECURED');
				}
			}
		}
		return false;
	}

	/**
	 * Reset attempt counter upon successful user login.
	 */
	public function handleSuccessfulLogin($hookName, $args) {
		$clientIp = $this->getClientIp();
		$user = is_array($args) && isset($args[0]) ? $args[0] : null;
		$username = '';
		if ($user && method_exists($user, 'getUsername')) {
			$username = strtolower(trim($user->getUsername()));
		} elseif (isset($_POST['username'])) {
			$username = strtolower(trim((string)$_POST['username']));
		}

		if (!empty($username)) {
			$lockKey = md5($clientIp . '_' . $username);
			$attemptsFile = $this->getStorageDir() . '/attempts.json';
			$this->updateJsonAtomic($attemptsFile, function($attempts) use ($lockKey) {
				unset($attempts[$lockKey]);
				return $attempts;
			});
			$this->logSecurityEvent('LOGIN_SUCCESS', "User: $username | IP: $clientIp | Counter reset", 'AUTH');
		}

		return false;
	}

	/**
	 * Direct hook handler for failed login events.
	 */
	public function handleFailedLoginHook($hookName, $args) {
		$username = is_array($args) && isset($args[0]) ? strtolower(trim((string)$args[0])) : '';
		if (empty($username) && isset($_POST['username'])) {
			$username = strtolower(trim((string)$_POST['username']));
		}
		if (!empty($username)) {
			$this->recordFailedLogin('User::loginFailed', [$username]);
		}
		return false;
	}

	/**
	 * Early check for active lockouts on login POST and fallback shutdown verifier.
	 */
	public function interceptLoginAttempts($hookName, $args) {
		if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
			$username = strtolower(trim((string)$_POST['username']));
			$clientIp = $this->getClientIp();
			$storageDir = $this->getStorageDir();
			$lockFile = $storageDir . '/lockouts.json';
			$lockouts = $this->readJsonFile($lockFile);

			$lockKey = md5($clientIp . '_' . $username);
			$now = time();

			// 1. Check if user + IP is actively locked out
			if (isset($lockouts[$lockKey]) && $lockouts[$lockKey]['expires'] > $now) {
				$remaining = ceil(($lockouts[$lockKey]['expires'] - $now) / 60);
				$this->logSecurityEvent('BRUTE_FORCE_BLOCKED', "User: $username | IP: $clientIp | Locked for $remaining more mins", 'REJECTED');
				$this->renderLockoutPage($username, $remaining);
				exit;
			}

			// 2. Fallback tracking on shutdown: ONLY increment if authentication actually failed!
			$self = $this;
			register_shutdown_function(function() use ($username, $clientIp, $lockKey, $storageDir, $self) {
				// Prevent double-counting if User::loginFailed already handled it
				if (!empty($GLOBALS['ojs_sec_failed_' . $lockKey])) {
					return;
				}

				$isLoggedIn = false;
				$request = PKPApplication::get()->getRequest();
				if ($request && $request->getUser()) {
					$isLoggedIn = true;
				}
				if (!$isLoggedIn && class_exists('\\PKP\\session\\SessionManager')) {
					$sessionMgr = \PKP\session\SessionManager::getManager();
					$session = $sessionMgr ? $sessionMgr->getUserSession() : null;
					if ($session && $session->getUserId()) {
						$isLoggedIn = true;
					}
				}
				if (!$isLoggedIn && !empty($_SESSION['userId'])) {
					$isLoggedIn = true;
				}

				if ($isLoggedIn) {
					// User successfully logged in: reset counter
					$attemptsFile = $storageDir . '/attempts.json';
					$self->updateJsonAtomic($attemptsFile, function($attempts) use ($lockKey) {
						unset($attempts[$lockKey]);
						return $attempts;
					});
				} else {
					// Genuine authentication failure
					$self->recordFailedLogin('Validation::loginFailed', [$username]);
				}
			});
		}

		return false;
	}

	/**
	 * Atomically record a failed login attempt and apply lockout when threshold is reached.
	 */
	public function recordFailedLogin($hookName, $args) {
		$username = is_array($args) && isset($args[0]) ? strtolower(trim((string)$args[0])) : 'unknown';
		$clientIp = $this->getClientIp();
		$storageDir = $this->getStorageDir();
		$lockKey = md5($clientIp . '_' . $username);
		$GLOBALS['ojs_sec_failed_' . $lockKey] = true;

		$attemptsFile = $storageDir . '/attempts.json';
		$lockFile = $storageDir . '/lockouts.json';
		$now = time();
		$self = $this;

		$this->updateJsonAtomic($attemptsFile, function($attempts) use ($lockKey, $username, $clientIp, $now, $lockFile, $self) {
			if (!isset($attempts[$lockKey]) || ($now - $attempts[$lockKey]['first_at']) > 900) {
				$attempts[$lockKey] = ['count' => 1, 'first_at' => $now, 'username' => $username, 'ip' => $clientIp];
			} else {
				$attempts[$lockKey]['count']++;
			}

			$count = $attempts[$lockKey]['count'];

			if ($count >= 5) {
				$self->updateJsonAtomic($lockFile, function($lockouts) use ($lockKey, $username, $clientIp, $now, $count) {
					$lockouts[$lockKey] = [
						'username' => $username,
						'ip' => $clientIp,
						'locked_at' => $now,
						'expires' => $now + 300,
						'attempts' => $count
					];
					return $lockouts;
				});
				unset($attempts[$lockKey]);
				$self->logSecurityEvent('ACCOUNT_LOCKED', "Username: $username | IP: $clientIp | Reached 5 failed attempts. Locked 5 mins.", 'LOCKOUT');
			} else {
				$self->logSecurityEvent('LOGIN_FAILED', "Username: $username | IP: $clientIp | Attempt $count/5", 'WARNING');
			}

			return $attempts;
		});

		return false;
	}

	public function renderLockoutPage($username, $remaining) {
		header('HTTP/1.1 429 Too Many Requests');
		header('Content-Type: text/html; charset=UTF-8');
		?>
		<!DOCTYPE html>
		<html lang="id">
		<head>
			<meta charset="UTF-8">
			<title>Akun Terkunci Sementara - OJS Security</title>
			<style>
				body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; color: #f8fafc; }
				.card { background: #1e293b; padding: 36px; border-radius: 12px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); max-width: 480px; text-align: center; border: 1px solid #334155; }
				h2 { color: #f87171; margin-top: 0; font-size: 22px; display: flex; align-items: center; justify-content: center; gap: 8px; }
				p { color: #cbd5e1; line-height: 1.6; margin: 16px 0; font-size: 14px; }
				a { color: #38bdf8; text-decoration: none; font-weight: 600; display: inline-block; margin-top: 14px; }
				a:hover { text-decoration: underline; }
			</style>
		</head>
		<body>
			<div class="card">
				<h2>⚠️ Akses Dibatasi</h2>
				<p style="font-size:16px; margin: 20px 0; color:#f1f5f9;">Terlalu banyak percobaan salah, tunggu <?php echo intval($remaining); ?> menit untuk mencoba kembali.</p>
				<a href="javascript:history.back()">« Kembali ke Halaman Login</a>
			</div>
		</body>
		</html>
		<?php
	}

	/**
	 * Inject security headers and login notice banner.
	 */
	public function injectUiAndHeaders($hookName, $args) {
		$templateMgr =& $args[0];
		$template = $args[1] ?? '';

		if (!headers_sent()) {
			@header('X-Content-Type-Options: nosniff');
			@header('X-XSS-Protection: 1; mode=block');
			@header('Referrer-Policy: strict-origin-when-cross-origin');
		}

		if (strpos($template, 'userLogin.tpl') !== false || strpos($template, 'login.tpl') !== false) {
			$noticeHtml = '
			<div class="ojs-security-notice" style="margin: 15px 0; padding: 12px 16px; border-radius: 6px; font-size: 13px; line-height: 1.5; background-color: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; display: flex; align-items: center; gap: 10px;">
				<span style="font-size: 18px;">🛡️</span>
				<div>
					<strong>Perlindungan Akun Aktif:</strong> Menghindari brute force, sistem menerapkan batas maksimal 5x percobaan gagal.
				</div>
			</div>';

			$filterCallback = function($output) use ($noticeHtml) {
				if (strpos($output, '</form>') !== false) {
					return str_replace('</form>', $noticeHtml . '</form>', $output);
				}
				return $output . $noticeHtml;
			};

			if (method_exists($templateMgr, 'registerFilter')) {
				$templateMgr->registerFilter('output', $filterCallback);
			} elseif (method_exists($templateMgr, 'register_outputfilter')) {
				$templateMgr->register_outputfilter($filterCallback);
			}
		}

		return false;
	}

	/**
	 * Handle Secret Monitoring Dashboard Request (?sec_dash=1 or ?sec_admin=1).
	 */
	public function handleDashboardRequest() {
		if (!isset($_GET['sec_dash']) && !isset($_GET['sec_admin'])) {
			return;
		}

		if (session_status() === PHP_SESSION_NONE) {
			@session_start();
		}

		$storageDir = $this->getStorageDir();
		$masterPass = $this->getMasterPassword();
		$configFile = $storageDir . '/config.json';
		$config = $this->readJsonFile($configFile);

		// CSRF Token generation
		if (empty($_SESSION['ojs_sec_csrf'])) {
			$_SESSION['ojs_sec_csrf'] = bin2hex(random_bytes(16));
		}
		$csrfToken = $_SESSION['ojs_sec_csrf'];

		// Handle Logout
		if (isset($_GET['logout'])) {
			unset($_SESSION['ojs_sec_auth']);
			header('Location: ?sec_dash=1');
			exit;
		}

		// Handle Unlock Action (Protected by CSRF)
		if (isset($_GET['unlock']) && !empty($_SESSION['ojs_sec_auth'])) {
			$unlockKey = (string)$_GET['unlock'];
			$token = (string)($_GET['csrf'] ?? '');
			if (!hash_equals($csrfToken, $token)) {
				header('HTTP/1.1 403 Forbidden');
				die('Security Error: Invalid CSRF Token');
			}

			$lockFile = $storageDir . '/lockouts.json';
			$this->updateJsonAtomic($lockFile, function($lockouts) use ($unlockKey, $storageDir) {
				if (isset($lockouts[$unlockKey])) {
					$unlockedUser = $lockouts[$unlockKey]['username'];
					unset($lockouts[$unlockKey]);
					$this->logSecurityEvent('MANUAL_UNLOCK', "Unlocked account: $unlockedUser from Dashboard", 'SUCCESS');
				}
				return $lockouts;
			});

			header('Location: ?sec_dash=1');
			exit;
		}

		// Dashboard Rate Limiting Check
		$clientIp = $this->getClientIp();
		$dashKey = md5($clientIp . '_dash');
		$dashAttemptsFile = $storageDir . '/dashboard_attempts.json';
		$dashAttempts = $this->readJsonFile($dashAttemptsFile);
		$now = time();

		$isDashLocked = false;
		$remainingLock = 0;
		if (isset($dashAttempts[$dashKey]) && $dashAttempts[$dashKey]['count'] >= 5) {
			$elapsed = $now - $dashAttempts[$dashKey]['last_at'];
			if ($elapsed < 600) {
				$isDashLocked = true;
				$remainingLock = ceil((600 - $elapsed) / 60);
			} else {
				// Expired: reset attempts
				unset($dashAttempts[$dashKey]);
				$this->writeJsonFile($dashAttemptsFile, $dashAttempts);
			}
		}

		$loginError = '';
		if ($isDashLocked) {
			$loginError = "Terlalu banyak percobaan salah. Akses dashboard dikunci selama {$remainingLock} menit.";
		} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sec_password'])) {
			$entered = (string)$_POST['sec_password'];
			$isValid = false;

			if (!empty($config['master_password_hash'])) {
				$isValid = password_verify($entered, $config['master_password_hash']);
			}
			if (!$isValid && !empty($masterPass)) {
				$isValid = hash_equals($masterPass, $entered);
			}

			if ($isValid) {
				// Reset dashboard failed attempts
				$this->updateJsonAtomic($dashAttemptsFile, function($attempts) use ($dashKey) {
					unset($attempts[$dashKey]);
					return $attempts;
				});
				session_regenerate_id(true);
				$_SESSION['ojs_sec_auth'] = true;
				header('Location: ?sec_dash=1');
				exit;
			} else {
				// Increment dashboard failed attempts
				$this->updateJsonAtomic($dashAttemptsFile, function($attempts) use ($dashKey, $now) {
					if (!isset($attempts[$dashKey]) || ($now - $attempts[$dashKey]['last_at']) > 600) {
						$attempts[$dashKey] = ['count' => 1, 'last_at' => $now];
					} else {
						$attempts[$dashKey]['count']++;
						$attempts[$dashKey]['last_at'] = $now;
					}
					return $attempts;
				});

				$loginError = 'Password keamanan salah. Akses ditolak!';
				$this->logSecurityEvent('DASHBOARD_LOGIN_FAILED', 'Failed login attempt on Secret Dashboard', 'FAILED');
			}
		}

		if (empty($_SESSION['ojs_sec_auth'])) {
			$this->renderDashboardLogin($loginError, $isDashLocked);
			exit;
		}

		$this->renderDashboardView($storageDir, $csrfToken);
		exit;
	}

	public function esc($string) {
		return htmlspecialchars((string)$string, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	}

	public function renderDashboardLogin($error = '', $disabled = false) {
		header('Content-Type: text/html; charset=UTF-8');
		?>
		<!DOCTYPE html>
		<html lang="id">
		<head>
			<meta charset="UTF-8">
			<title>OJS Security Suite - Authenticate</title>
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<style>
				* { box-sizing: border-box; margin: 0; padding: 0; }
				body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
				.card { background: #1e293b; padding: 36px; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5); border: 1px solid #334155; }
				.logo { text-align: center; margin-bottom: 24px; }
				.logo span { font-size: 44px; }
				h2 { font-size: 20px; text-align: center; margin-bottom: 8px; color: #38bdf8; }
				p.subtitle { text-align: center; font-size: 13px; color: #94a3b8; margin-bottom: 24px; }
				.form-group { margin-bottom: 20px; }
				label { display: block; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #cbd5e1; margin-bottom: 6px; }
				input[type="password"] { width: 100%; padding: 12px 14px; background: #0f172a; border: 1px solid #475569; border-radius: 6px; color: #fff; font-size: 14px; outline: none; }
				input[type="password"]:focus { border-color: #38bdf8; box-shadow: 0 0 0 2px rgba(56,189,248,0.2); }
				button { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; }
				button:hover { background: #1d4ed8; }
				button:disabled { background: #475569; cursor: not-allowed; }
				.error { background: #450a0a; color: #f87171; border: 1px solid #991b1b; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-bottom: 18px; }
			</style>
		</head>
		<body>
			<div class="card">
				<div class="logo"><span>🛡️</span></div>
				<h2>Security Monitoring Panel</h2>
				<p class="subtitle">OJS Virtual Patch & Hardening System</p>
				<?php if (!empty($error)): ?><div class="error"><?php echo $this->esc($error); ?></div><?php endif; ?>
				<form method="POST">
					<div class="form-group">
						<label for="sec_password">Master Security Key</label>
						<input type="password" id="sec_password" name="sec_password" placeholder="Masukkan Security Password..." required <?php echo $disabled ? 'disabled' : 'autofocus'; ?>>
					</div>
					<button type="submit" <?php echo $disabled ? 'disabled' : ''; ?>>Buka Dashboard</button>
				</form>
			</div>
		</body>
		</html>
		<?php
	}

	public function renderDashboardView($storageDir, $csrfToken) {
		$lockFile = $storageDir . '/lockouts.json';
		$lockouts = $this->readJsonFile($lockFile);
		$logFile = $storageDir . '/security_audit.log';

		$totalEvents = 0;
		$bruteBlocks = 0;
		$redirectBlocks = 0;
		$recentLogs = [];

		if (file_exists($logFile)) {
			$rawLines = array_filter(explode("\n", file_get_contents($logFile)));
			$cleanLines = [];
			foreach ($rawLines as $rl) {
				if (strpos($rl, '<?php') !== false) continue;
				$cleanLines[] = $rl;
			}
			$lines = array_reverse($cleanLines);
			$totalEvents = count($lines);
			$count = 0;
			foreach ($lines as $line) {
				if (strpos($line, 'BRUTE_FORCE') !== false || strpos($line, 'ACCOUNT_LOCKED') !== false) $bruteBlocks++;
				if (strpos($line, 'OPEN_REDIRECT') !== false) $redirectBlocks++;
				if ($count < 30) {
					$recentLogs[] = $line;
					$count++;
				}
			}
		}

		header('Content-Type: text/html; charset=UTF-8');
		?>
		<!DOCTYPE html>
		<html lang="id">
		<head>
			<meta charset="UTF-8">
			<title>OJS Security Hardener - Live Dashboard</title>
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<style>
				* { box-sizing: border-box; margin: 0; padding: 0; }
				body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b1329; color: #f1f5f9; padding: 24px; }
				.container { max-width: 1200px; margin: 0 auto; }
				header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #1e293b; }
				h1 { font-size: 24px; display: flex; align-items: center; gap: 10px; color: #38bdf8; }
				.btn-logout { background: #334155; color: #f8fafc; padding: 8px 16px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600; }
				.btn-logout:hover { background: #475569; }
				.grid-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; margin-bottom: 24px; }
				.stat-card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; }
				.stat-card h3 { font-size: 13px; text-transform: uppercase; color: #94a3b8; margin-bottom: 8px; }
				.stat-card .value { font-size: 30px; font-weight: 700; color: #f8fafc; }
				.stat-card.accent { border-left: 4px solid #38bdf8; }
				.stat-card.danger { border-left: 4px solid #ef4444; }
				.stat-card.warning { border-left: 4px solid #f59e0b; }
				.stat-card.success { border-left: 4px solid #10b981; }
				.badges { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 24px; background: #1e293b; padding: 14px; border-radius: 8px; border: 1px solid #334155; }
				.badge { background: #064e3b; color: #34d399; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; }
				.panel { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; margin-bottom: 24px; }
				.panel h2 { font-size: 16px; margin-bottom: 16px; color: #cbd5e1; }
				table { width: 100%; border-collapse: collapse; font-size: 13px; }
				th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
				th { background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }
				tr:hover td { background: #1a2333; }
				.btn-unlock { background: #0284c7; color: #fff; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 4px; }
				.btn-unlock:hover { background: #0369a1; }
				pre.log-viewer { background: #090d16; padding: 16px; border-radius: 6px; font-family: monospace; font-size: 12px; color: #a5f3fc; overflow-x: auto; max-height: 400px; }
			</style>
		</head>
		<body>
			<div class="container">
				<header>
					<h1>🛡️ OJS Security & Threat Monitoring</h1>
					<a href="?sec_dash=1&logout=1" class="btn-logout">Logout</a>
				</header>

				<div class="badges">
					<span style="color:#94a3b8; font-size:12px; margin-right:4px;">Virtual Patches Active:</span>
					<span class="badge">✓ CVE-2024-56525 (User XML SuperAdmin Block)</span>
					<span class="badge">✓ CVE-2024-7902 (Open Redirect)</span>
					<span class="badge">✓ CVE-2022-24181 (Host Header XSS)</span>
					<span class="badge">✓ CVE-2026-19906 (API Token CSPRNG)</span>
					<span class="badge">✓ Anti Brute-force Hybrid Lockout</span>
				</div>

				<div class="grid-stats">
					<div class="stat-card accent">
						<h3>Total Threat Events Logged</h3>
						<div class="value"><?php echo $totalEvents; ?></div>
					</div>
					<div class="stat-card danger">
						<h3>Brute-force Attacks Blocked</h3>
						<div class="value"><?php echo $bruteBlocks; ?></div>
					</div>
					<div class="stat-card warning">
						<h3>Open Redirect Intercepted</h3>
						<div class="value"><?php echo $redirectBlocks; ?></div>
					</div>
					<div class="stat-card success">
						<h3>Currently Locked Accounts</h3>
						<div class="value"><?php echo count($lockouts); ?></div>
					</div>
				</div>

				<div class="panel">
					<h2>🔒 Akun / IP Yang Sedang Dikunci Sementara (Active Lockouts)</h2>
					<?php if (empty($lockouts)): ?>
						<p style="color:#64748b; font-size:13px;">Tidak ada akun yang sedang terkunci saat ini. Semua login aman.</p>
					<?php else: ?>
						<table>
							<thead>
								<tr>
									<th>Username</th>
									<th>IP Address</th>
									<th>Waktu Terkunci</th>
									<th>Sisa Waktu</th>
									<th>Aksi Buka Kunci</th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ($lockouts as $key => $item): 
									$remaining = max(0, ceil(($item['expires'] - time()) / 60));
								?>
								<tr>
									<td><strong><?php echo $this->esc($item['username']); ?></strong></td>
									<td><code><?php echo $this->esc($item['ip']); ?></code></td>
									<td><?php echo date('H:i:s d/m/Y', $item['locked_at']); ?></td>
									<td><span style="color:#f87171; font-weight:600;"><?php echo $remaining; ?> Menit</span></td>
									<td><a href="?sec_dash=1&unlock=<?php echo urlencode($key); ?>&csrf=<?php echo urlencode($csrfToken); ?>" class="btn-unlock" onclick="return confirm('Buka kunci akun ini sekarang?')">🔓 Quick Unlock (Buka Akun)</a></td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>

				<div class="panel">
					<h2>📋 Real-time Live Security Audit Log (Last 30 Events)</h2>
					<pre class="log-viewer"><?php 
						if (empty($recentLogs)) {
							echo "[INFO] Belum ada insiden keamanan yang tercatat. Sistem dalam kondisi aman sentosa.\n";
						} else {
							foreach ($recentLogs as $l) {
								echo $this->esc($l) . "\n";
							}
						}
					?></pre>
				</div>
			</div>
		</body>
		</html>
		<?php
	}

	public function logSecurityEvent($eventType, $details, $status = 'INFO') {
		$storageDir = $this->getStorageDir();
		$logFile = $storageDir . '/security_audit.log';
		if (!file_exists($logFile)) {
			$header = "<?php http_response_code(403); exit('403 Forbidden'); ?>\n";
			@file_put_contents($logFile, $header, LOCK_EX);
		}
		$ip = $this->getClientIp();
		$timestamp = date('Y-m-d H:i:s');
		$entry = sprintf("[%s] [%s] IP: %s | %s | ACTION: %s\n", $timestamp, $eventType, $ip, $details, $status);
		@file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
	}

	public function getClientIp() {
		$remoteAddr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';

		$trustForwarded = false;
		if (class_exists('\\PKP\\config\\Config')) {
			$trustForwarded = (bool) \PKP\config\Config::getVar('general', 'trust_x_forwarded_for');
		} elseif (class_exists('Config')) {
			$trustForwarded = (bool) Config::getVar('general', 'trust_x_forwarded_for');
		}

		// Only trust proxy headers when trust_x_forwarded_for is explicitly enabled in config.inc.php
		if ($trustForwarded) {
			if (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
				return $_SERVER['HTTP_CF_CONNECTING_IP'];
			}
			if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
				$ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
				$client = trim($ips[0]);
				if (filter_var($client, FILTER_VALIDATE_IP)) {
					return $client;
				}
			}
		}

		return $remoteAddr;
	}

	public function getStorageDir() {
		// Priority 1: OJS private files_dir if available
		$filesDir = Config::getVar('files', 'files_dir');
		if (!empty($filesDir) && is_dir($filesDir)) {
			$secDir = rtrim($filesDir, '/') . '/security_hardener';
			if (!is_dir($secDir)) {
				@mkdir($secDir, 0775, true);
			}
			if (is_dir($secDir) && is_writable($secDir)) {
				$this->protectStorageDir($secDir);
				return $secDir;
			}
		}

		// Priority 2: Local data directory within plugin
		$dir = __DIR__ . '/data';
		if (!is_dir($dir)) {
			@mkdir($dir, 0775, true);
		}
		$this->protectStorageDir($dir);
		return $dir;
	}

	public function readJsonFile($path) {
		if (!file_exists($path)) return [];
		$content = @file_get_contents($path);
		if ($content === false) return [];
		if (substr($content, 0, 5) === '<?php') {
			$firstNewline = strpos($content, "\n");
			$content = ($firstNewline !== false) ? substr($content, $firstNewline + 1) : '';
		}
		$data = @json_decode($content, true);
		return is_array($data) ? $data : [];
	}

	public function writeJsonFile($path, $data) {
		$payload = "<?php http_response_code(403); exit('403 Forbidden'); ?>\n" . json_encode($data, JSON_PRETTY_PRINT);
		@file_put_contents($path, $payload, LOCK_EX);
	}

	public function protectStorageDir($dir) {
		if (!is_dir($dir)) return;
		$indexPhp = $dir . '/index.php';
		if (!file_exists($indexPhp)) {
			@file_put_contents($indexPhp, "<?php\nhttp_response_code(403);\nheader('HTTP/1.1 403 Forbidden');\nexit('403 Forbidden');\n");
		}
		$htaccess = $dir . '/.htaccess';
		if (!file_exists($htaccess)) {
			@file_put_contents($htaccess, "# Deny all direct web access\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n");
		}
		$webconfig = $dir . '/web.config';
		if (!file_exists($webconfig)) {
			@file_put_contents($webconfig, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <authorization>\n      <deny users=\"*\" />\n    </authorization>\n  </system.webServer>\n</configuration>\n");
		}
		$indexHtml = $dir . '/index.html';
		if (!file_exists($indexHtml)) {
			@file_put_contents($indexHtml, "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>");
		}
	}

	public function getMasterPassword() {
		if (method_exists($this, 'getSetting')) {
			$pass = $this->getSetting(0, 'master_password');
			if (!empty($pass)) return $pass;
		}

		$storageDir = $this->getStorageDir();
		$configFile = $storageDir . '/config.json';
		$config = $this->readJsonFile($configFile);
		if (!empty($config['master_password'])) {
			return $config['master_password'];
		}

		// Generate secure cryptographic master key
		$generatedPass = 'Sec_' . bin2hex(random_bytes(10)) . '!';

		$config['master_password'] = $generatedPass;
		$config['master_password_hash'] = password_hash($generatedPass, PASSWORD_DEFAULT);
		$config['generated_at'] = date('Y-m-d H:i:s');
		$this->writeJsonFile($configFile, $config);
		@chmod($configFile, 0600);

		if (method_exists($this, 'updateSetting')) {
			$this->updateSetting(0, 'master_password', $generatedPass, 'string');
		}

		$this->logSecurityEvent('SECURITY_KEY_INIT', 'Generated secure master password for Secret Dashboard', 'INITIALIZED');
		return $generatedPass;
	}

	public function updateJsonAtomic($path, $callback) {
		$fp = @fopen($path, 'c+');
		if (!$fp) return false;

		$result = false;
		if (@flock($fp, LOCK_EX)) {
			$filesize = @filesize($path);
			$content = ($filesize > 0) ? @fread($fp, $filesize) : '';
			if (substr($content, 0, 5) === '<?php') {
				$firstNewline = strpos($content, "\n");
				$content = ($firstNewline !== false) ? substr($content, $firstNewline + 1) : '';
			}
			$data = @json_decode($content, true);
			if (!is_array($data)) $data = [];

			$data = call_user_func($callback, $data);

			$payload = "<?php http_response_code(403); exit('403 Forbidden'); ?>\n" . json_encode($data, JSON_PRETTY_PRINT);
			@ftruncate($fp, 0);
			@rewind($fp);
			@fwrite($fp, $payload);
			@fflush($fp);
			@flock($fp, LOCK_UN);
			$result = $data;
		}
		@fclose($fp);
		return $result;
	}

}
