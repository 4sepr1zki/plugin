<?php

/**
 * @file classes/SecurityHardenerCore.php
 *
 * Copyright (c) 2026
 * Distributed under the GNU GPL v3.
 *
 * @class SecurityHardenerCore
 * @brief Core engine and business logic for OJS Security Hardener.
 * Shared across OJS 2.4.x - 3.4+ entry points.
 */

class SecurityHardenerCore {
	private static $instance = null;
	protected $plugin = null;
	protected $storageDir = null;

	public function __construct($plugin = null) {
		$this->plugin = $plugin;
	}

	public static function getInstance($plugin = null) {
		if (self::$instance === null) {
			self::$instance = new self($plugin);
		} elseif ($plugin !== null && self::$instance->plugin === null) {
			self::$instance->plugin = $plugin;
		}
		return self::$instance;
	}

	/**
	 * Real Virtual Patch for CVE-2024-56525 (User XML Privilege Escalation) & Generic XXE in uploads.
	 */
	public function inspectUploadedFiles($hookName = null, $args = null) {
		if ($_SERVER['REQUEST_METHOD'] !== 'POST' || empty($_FILES)) {
			return false;
		}

		foreach ($_FILES as $file) {
			$tmpNames = is_array($file['tmp_name']) ? $file['tmp_name'] : array($file['tmp_name']);
			$names = is_array($file['name']) ? $file['name'] : array($file['name']);

			foreach ($tmpNames as $idx => $path) {
				if (empty($path) || !is_uploaded_file($path)) continue;
				$filename = strtolower(isset($names[$idx]) ? $names[$idx] : '');

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
					if (preg_match('/(<role_id>\s*1\s*<\/role_id>|<context_id>\s*0\s*<\/context_id>|<user_group_ref[^>]*>[^<]*Site\s*Admin|<name[^>]*>[^<]*Site\s*Admin|ROLE_ID_SITE_ADMIN)/i', $content)) {
						$isSiteAdmin = false;
						if (class_exists('Validation') && method_exists('Validation', 'isSiteAdmin')) {
							$isSiteAdmin = Validation::isSiteAdmin();
						} elseif (class_exists('Application')) {
							$req = Application::get()->getRequest();
							$user = $req ? $req->getUser() : null;
							if ($user && method_exists($user, 'hasRole')) {
								$isSiteAdmin = $user->hasRole(array(1), 0); // ROLE_ID_SITE_ADMIN = 1
							}
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

		return false;
	}

	/**
	 * Mitigate CVE-2024-7902 & CVE-2024-46326: Sanitize URL before sending HTTP Location header.
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

		$allowedHosts = array();
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
				} else {
					$secureToken = bin2hex(openssl_random_pseudo_bytes(32));
				}
				$form->setData('apiKey', $secureToken);
				$this->logSecurityEvent('API_TOKEN', 'Regenerated API token using CSPRNG', 'SECURED');
			}
		}
		return false;
	}

	/**
	 * Early Login Interception for Brute Force Detection & Lockout Enforcement.
	 */
	public function interceptLoginAttempts($hookName = null, $args = null) {
		$clientIp = $this->getClientIp();
		$now = time();

		// Check Active Lockouts
		$storageDir = $this->getStorageDir();
		$lockFile = $storageDir . '/lockouts.json';
		$lockouts = $this->readJsonFile($lockFile);

		if (!empty($lockouts)) {
			$activeLockouts = array();
			$hasExpired = false;

			foreach ($lockouts as $k => $info) {
				if (isset($info['expires']) && $now < $info['expires']) {
					$activeLockouts[$k] = $info;
				} else {
					$hasExpired = true;
				}
			}

			if ($hasExpired) {
				$this->updateJsonAtomic($lockFile, function($data) use ($activeLockouts) {
					return $activeLockouts;
				});
				$lockouts = $activeLockouts;
			}

			// Check IP Lockout
			$ipKey = md5('ip_' . $clientIp);
			if (isset($lockouts[$ipKey])) {
				$remaining = ceil(($lockouts[$ipKey]['expires'] - $now) / 60);
				$this->logSecurityEvent('BRUTE_FORCE_BLOCKED', "IP: $clientIp | Locked for $remaining more mins", 'REJECTED');
				$this->renderLockoutPage('Alamat IP Anda', $remaining);
				exit;
			}

			// Check Username Lockout on POST
			if ($_SERVER['REQUEST_METHOD'] === 'POST') {
				$submittedUser = '';
				if (isset($_POST['username'])) {
					$submittedUser = trim((string)$_POST['username']);
				} elseif (isset($_POST['email'])) {
					$submittedUser = trim((string)$_POST['email']);
				}

				if ($submittedUser !== '') {
					$userKey = md5('usr_' . strtolower($submittedUser));
					if (isset($lockouts[$userKey])) {
						$remaining = ceil(($lockouts[$userKey]['expires'] - $now) / 60);
						$this->logSecurityEvent('BRUTE_FORCE_BLOCKED', "User: $submittedUser | IP: $clientIp | Locked for $remaining more mins", 'REJECTED');
						$this->renderLockoutPage($submittedUser, $remaining);
						exit;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Reset counter on successful user login.
	 */
	public function handleSuccessfulLogin($hookName, $args) {
		$clientIp = $this->getClientIp();
		$user = is_array($args) && isset($args[0]) ? $args[0] : null;
		$username = '';
		if ($user && method_exists($user, 'getUsername')) {
			$username = $user->getUsername();
		}

		$storageDir = $this->getStorageDir();
		$attemptsFile = $storageDir . '/attempts.json';

		$userKey = $username ? md5('usr_' . strtolower($username)) : null;
		$ipKey = md5('ip_' . $clientIp);

		$this->updateJsonAtomic($attemptsFile, function($attempts) use ($userKey, $ipKey) {
			if ($userKey && isset($attempts[$userKey])) unset($attempts[$userKey]);
			if (isset($attempts[$ipKey])) unset($attempts[$ipKey]);
			return $attempts;
		});

		$this->logSecurityEvent('LOGIN_SUCCESS', "User: $username | IP: $clientIp", 'SUCCESS');
		return false;
	}

	/**
	 * Record failed login and trigger lockout if threshold is exceeded.
	 */
	public function handleFailedLoginHook($hookName, $args) {
		$clientIp = $this->getClientIp();
		$username = '';
		if (isset($_POST['username'])) {
			$username = trim((string)$_POST['username']);
		} elseif (isset($_POST['email'])) {
			$username = trim((string)$_POST['email']);
		}

		$storageDir = $this->getStorageDir();
		$attemptsFile = $storageDir . '/attempts.json';
		$lockFile = $storageDir . '/lockouts.json';
		$now = time();

		$lockKey = $username ? md5('usr_' . strtolower($username)) : md5('ip_' . $clientIp);
		$self = $this;

		$this->updateJsonAtomic($attemptsFile, function($attempts) use ($lockKey, $username, $clientIp, $now, $lockFile, $self) {
			if (!isset($attempts[$lockKey]) || ($now - $attempts[$lockKey]['last_at']) > 300) {
				$attempts[$lockKey] = array('count' => 1, 'last_at' => $now, 'ip' => $clientIp, 'user' => $username);
			} else {
				$attempts[$lockKey]['count']++;
				$attempts[$lockKey]['last_at'] = $now;
			}

			$count = $attempts[$lockKey]['count'];

			// Threshold: 5 failed attempts within 5 minutes -> Lock for 5 minutes (300s)
			if ($count >= 5) {
				$self->updateJsonAtomic($lockFile, function($lockouts) use ($lockKey, $username, $clientIp, $now, $count) {
					$lockouts[$lockKey] = array(
						'username' => $username ? $username : 'IP: ' . $clientIp,
						'ip' => $clientIp,
						'locked_at' => $now,
						'expires' => $now + 300,
						'attempts' => $count
					);
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

	/**
	 * Validate User Registration Password Strength (Backend Enforcement).
	 */
	public function validateRegistrationPassword($hookName, $args) {
		$form = is_array($args) && isset($args[0]) ? $args[0] : null;
		if ($form && method_exists($form, 'getData') && method_exists($form, 'addError')) {
			$password = (string)$form->getData('password');
			if ($password !== '' && strlen($password) < 8) {
				$msg = 'Kata sandi minimal 8 karakter dengan kombinasi yang sulit ditebak.';
				$form->addError('password', $msg);
				$this->logSecurityEvent('WEAK_PASSWORD_REJECTED', 'Blocked user registration with password under 8 characters', 'REJECTED');
			}
		}
		return false;
	}

	/**
	 * Inject Security Notice Banner into Login & Register Pages & Global Security Headers
	 */
	public function injectUiAndHeaders($hookName, $args) {
		$templateMgr =& $args[0];
		$template = isset($args[1]) ? $args[1] : '';

		if (!headers_sent()) {
			@header('X-Content-Type-Options: nosniff');
			@header('X-XSS-Protection: 1; mode=block');
			@header('Referrer-Policy: strict-origin-when-cross-origin');
		}

		// Login page filter
		if (strpos($template, 'userLogin.tpl') !== false || strpos($template, 'login.tpl') !== false) {
			if (method_exists($templateMgr, 'registerFilter')) {
				$templateMgr->registerFilter('output', array($this, 'filterLoginOutput'));
			} elseif (method_exists($templateMgr, 'register_outputfilter')) {
				$templateMgr->register_outputfilter(array($this, 'filterLoginOutputLegacy'));
			}
		}

		// Registration page filter
		if (strpos($template, 'userRegister.tpl') !== false || strpos($template, 'register.tpl') !== false || strpos($template, 'registrationForm.tpl') !== false) {
			if (method_exists($templateMgr, 'registerFilter')) {
				$templateMgr->registerFilter('output', array($this, 'filterRegisterOutput'));
			} elseif (method_exists($templateMgr, 'register_outputfilter')) {
				$templateMgr->register_outputfilter(array($this, 'filterRegisterOutputLegacy'));
			}
		}

		return false;
	}

	public function filterLoginOutput($output, $smarty = null) {
		if (strpos($output, 'ojs-security-notice') !== false) {
			return $output;
		}
		$noticeHtml = '<div class="ojs-security-notice" style="margin: 15px 0 20px 0; padding: 12px 16px; border-radius: 6px; font-size: 13px; line-height: 1.5; background-color: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; display: flex; align-items: center; gap: 10px;"><span style="font-size: 18px;">🛡️</span><div><strong>Perlindungan Akun Aktif:</strong> Menghindari brute force, sistem menerapkan batas maksimal 5x percobaan gagal.</div></div>';
		$targets = array(
			'<nav class="cmp_breadcrumbs"',
			'<div class="page page_login">',
			'<div class="pkp_structure_main"'
		);
		foreach ($targets as $target) {
			if (strpos($output, $target) !== false) {
				return str_replace($target, $noticeHtml . "\n\t" . $target, $output);
			}
		}
		if (strpos($output, '<form') !== false) {
			$pos = strpos($output, '<form');
			return substr_replace($output, $noticeHtml . "\n\t<form", $pos, strlen('<form'));
		}
		return $output;
	}

	public function filterLoginOutputLegacy($output) {
		return $this->filterLoginOutput($output, null);
	}

	/**
	 * Injects Password Requirement Notice directly below the password input in the Registration form.
	 */
	public function filterRegisterOutput($output, $smarty = null) {
		if (strpos($output, 'ojs-password-hint') !== false) {
			return $output;
		}

		$hintHtml = '<div class="ojs-password-hint" style="margin-top: 6px; margin-bottom: 12px; padding: 6px 12px; border-radius: 4px; font-size: 12px; line-height: 1.4; background-color: #eff6ff; color: #1e40af; border: 1px solid #bfdbfe; display: flex; align-items: center; gap: 8px;"><span style="font-size: 14px;">🔒</span><span><strong>Ketentuan Kata Sandi:</strong> Minimal 8 karakter dengan kata sandi yang sulit ditebak.</span></div>';

		// Target: directly below password input
		$pattern = '/(<input[^>]*name=[\'"]password[\'"][^>]*>)/i';
		if (preg_match($pattern, $output)) {
			return preg_replace($pattern, "$1\n\t" . $hintHtml, $output, 1);
		}

		return $output;
	}

	public function filterRegisterOutputLegacy($output) {
		return $this->filterRegisterOutput($output, null);
	}

	/**
	 * Handle Secret Monitoring Dashboard Request (?sec_dash=1 or ?sec_admin=1)
	 * Integrated with OJS Site Admin access control + Emergency master password fallback.
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
			if (function_exists('random_bytes')) {
				$_SESSION['ojs_sec_csrf'] = bin2hex(random_bytes(16));
			} else {
				$_SESSION['ojs_sec_csrf'] = md5(uniqid(mt_rand(), true));
			}
		}
		$csrfToken = $_SESSION['ojs_sec_csrf'];

		// Check if logged in as an official OJS Site Admin
		$isOjsSiteAdmin = false;
		if (class_exists('Validation') && method_exists('Validation', 'isSiteAdmin')) {
			$isOjsSiteAdmin = Validation::isSiteAdmin();
		} elseif (class_exists('Application')) {
			$req = Application::get()->getRequest();
			$user = $req ? $req->getUser() : null;
			if ($user && method_exists($user, 'hasRole')) {
				$isOjsSiteAdmin = $user->hasRole(array(1), 0);
			}
		}

		// Handle Logout
		if (isset($_GET['logout'])) {
			unset($_SESSION['ojs_sec_auth']);
			header('Location: ?sec_dash=1');
			exit;
		}

		$isAuthorized = $isOjsSiteAdmin || !empty($_SESSION['ojs_sec_auth']);

		// Handle Unlock Action (Protected by CSRF and Authorization)
		if (isset($_GET['unlock']) && $isAuthorized) {
			$unlockKey = (string)$_GET['unlock'];
			$token = isset($_GET['csrf']) ? (string)$_GET['csrf'] : '';
			
			$validToken = false;
			if (function_exists('hash_equals')) {
				$validToken = hash_equals($csrfToken, $token);
			} else {
				$validToken = ($csrfToken === $token);
			}

			if (!$validToken) {
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

		// Rate Limiting for Emergency Login
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
				unset($dashAttempts[$dashKey]);
				$this->writeJsonFile($dashAttemptsFile, $dashAttempts);
			}
		}

		$loginError = '';
		if (!$isAuthorized && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sec_password'])) {
			if ($isDashLocked) {
				$loginError = "Terlalu banyak percobaan salah. Akses dashboard dikunci selama {$remainingLock} menit.";
			} else {
				$entered = (string)$_POST['sec_password'];
				$isValid = false;

				if (!empty($config['master_password_hash']) && function_exists('password_verify')) {
					$isValid = password_verify($entered, $config['master_password_hash']);
				}
				if (!$isValid && !empty($masterPass)) {
					if (function_exists('hash_equals')) {
						$isValid = hash_equals($masterPass, $entered);
					} else {
						$isValid = ($masterPass === $entered);
					}
				}

				if ($isValid) {
					$this->updateJsonAtomic($dashAttemptsFile, function($attempts) use ($dashKey) {
						unset($attempts[$dashKey]);
						return $attempts;
					});
					if (function_exists('session_regenerate_id')) {
						session_regenerate_id(true);
					}
					$_SESSION['ojs_sec_auth'] = true;
					header('Location: ?sec_dash=1');
					exit;
				} else {
					$this->updateJsonAtomic($dashAttemptsFile, function($attempts) use ($dashKey, $now) {
						if (!isset($attempts[$dashKey]) || ($now - $attempts[$dashKey]['last_at']) > 600) {
							$attempts[$dashKey] = array('count' => 1, 'last_at' => $now);
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
		}

		// Render Login or Full Dashboard
		header('HTTP/1.1 200 OK');
		header('Content-Type: text/html; charset=UTF-8');
		header('X-Robots-Tag: noindex, nofollow, noarchive');

		$esc = function($str) {
			return htmlspecialchars((string)$str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
		};

		if (!$isAuthorized) {
			$this->renderDashboardLoginForm($loginError, $isDashLocked, $remainingLock, $esc);
			exit;
		}

		// Full Dashboard View
		$this->renderDashboardMainView($storageDir, $csrfToken, $isOjsSiteAdmin, $esc);
		exit;
	}

	protected function renderDashboardLoginForm($loginError, $isDashLocked, $remainingLock, $esc) {
		?>
		<!DOCTYPE html>
		<html lang="id">
		<head>
			<meta charset="UTF-8">
			<title>Security Emergency Console - OJS</title>
			<style>
				body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #090d16; color: #f1f5f9; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
				.box { background: #111827; border: 1px solid #1f2937; padding: 32px; border-radius: 12px; width: 100%; max-width: 420px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
				h2 { margin: 0 0 8px 0; font-size: 20px; display: flex; align-items: center; gap: 8px; color: #60a5fa; }
				p { font-size: 13px; color: #94a3b8; margin: 0 0 20px 0; line-height: 1.5; }
				.notice-box { background: #1e293b; border-left: 3px solid #3b82f6; padding: 10px 14px; font-size: 12px; margin-bottom: 18px; border-radius: 0 6px 6px 0; }
				input[type="password"] { width: 100%; padding: 12px; background: #1f2937; border: 1px solid #374151; color: #fff; border-radius: 6px; box-sizing: border-box; font-size: 14px; margin-bottom: 16px; }
				input[type="password"]:focus { outline: none; border-color: #3b82f6; ring: 2px solid #3b82f6; }
				button { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px; transition: background 0.2s; }
				button:hover { background: #1d4ed8; }
				button:disabled { background: #475569; cursor: not-allowed; }
				.err { color: #f87171; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 16px; }
			</style>
		</head>
		<body>
			<div class="box">
				<h2>🛡️ Security Console</h2>
				<p>Akses Terintegrasi OJS Security Hardener</p>
				<div class="notice-box">
					<strong>💡 Info Akses:</strong> Jika Anda adalah Site Administrator OJS, silakan login ke OJS terlebih dahulu untuk akses langsung, atau gunakan Emergency Master Password di bawah.
				</div>
				<?php if ($loginError): ?>
					<div class="err"><?php echo $esc($loginError); ?></div>
				<?php endif; ?>
				<form method="POST">
					<input type="password" name="sec_password" placeholder="Emergency Master Password..." required <?php echo $isDashLocked ? 'disabled' : ''; ?> autofocus>
					<button type="submit" <?php echo $isDashLocked ? 'disabled' : ''; ?>>Buka Console</button>
				</form>
			</div>
		</body>
		</html>
		<?php
	}

	protected function renderDashboardMainView($storageDir, $csrfToken, $isOjsSiteAdmin, $esc) {
		$lockFile = $storageDir . '/lockouts.json';
		$lockouts = $this->readJsonFile($lockFile);
		$logFile = $storageDir . '/security_audit.log';

		$auditLogs = array();
		if (file_exists($logFile)) {
			$lines = @file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			if ($lines) {
				$auditLogs = array_reverse(array_slice($lines, -100));
			}
		}
		?>
		<!DOCTYPE html>
		<html lang="id">
		<head>
			<meta charset="UTF-8">
			<title>OJS Security Hardener - Live Console</title>
			<style>
				body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f8fafc; margin: 0; padding: 24px; }
				.wrap { max-width: 1200px; margin: 0 auto; }
				.topbar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px; }
				.topbar h1 { margin: 0; font-size: 22px; display: flex; align-items: center; gap: 10px; }
				.badge { background: #1e3a8a; color: #93c5fd; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
				.badge-admin { background: #065f46; color: #6ee7b7; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 600; }
				.logout { color: #f87171; text-decoration: none; font-size: 13px; font-weight: 600; padding: 6px 12px; border: 1px solid rgba(248, 113, 113, 0.3); border-radius: 6px; }
				.logout:hover { background: rgba(248, 113, 113, 0.1); }
				.card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 20px; margin-bottom: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
				h3 { margin: 0 0 16px 0; font-size: 16px; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
				table { width: 100%; border-collapse: collapse; font-size: 13px; }
				th, td { text-align: left; padding: 12px; border-bottom: 1px solid #1f2937; }
				th { color: #94a3b8; font-weight: 600; }
				tr:hover td { background: #1e293b; }
				.btn-unlock { background: #ef4444; color: #fff; padding: 6px 12px; border-radius: 6px; text-decoration: none; font-size: 12px; font-weight: 600; display: inline-block; }
				.btn-unlock:hover { background: #dc2626; }
				.logbox { background: #030712; padding: 16px; border-radius: 8px; font-family: ui-monospace, Menlo, Monaco, Consolas, monospace; font-size: 12px; max-height: 450px; overflow-y: auto; color: #a5f3fc; border: 1px solid #111827; line-height: 1.6; }
				.logline { margin-bottom: 4px; word-break: break-all; }
			</style>
		</head>
		<body>
			<div class="wrap">
				<div class="topbar">
					<h1>
						🛡️ OJS Security Hardener
						<?php if ($isOjsSiteAdmin): ?>
							<span class="badge-admin">OJS Site Administrator (Verified Session)</span>
						<?php else: ?>
							<span class="badge">Emergency Console Access</span>
						<?php endif; ?>
					</h1>
					<a href="?sec_dash=1&logout=1" class="logout">Tutup Console</a>
				</div>

				<div class="card">
					<h3>🚫 Akun Terkunci (Brute-Force Lockout)</h3>
					<?php if (empty($lockouts)): ?>
						<p style="color: #64748b; font-size: 14px; margin: 0;">Tidak ada akun atau IP yang sedang terkunci.</p>
					<?php else: ?>
						<table>
							<thead>
								<tr>
									<th>Target / Username</th>
									<th>IP Address</th>
									<th>Waktu Kunci</th>
									<th>Sisa Waktu</th>
									<th>Aksi</th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ($lockouts as $k => $info):
									$rem = ceil(($info['expires'] - time()) / 60);
									if ($rem <= 0) continue;
								?>
								<tr>
									<td><strong><?php echo $esc($info['username']); ?></strong></td>
									<td><code><?php echo $esc($info['ip']); ?></code></td>
									<td><?php echo date('Y-m-d H:i:s', $info['locked_at']); ?></td>
									<td><span style="color: #f87171; font-weight:600;"><?php echo intval($rem); ?> menit</span></td>
									<td>
										<a href="?sec_dash=1&unlock=<?php echo urlencode($k); ?>&csrf=<?php echo urlencode($csrfToken); ?>" class="btn-unlock" onclick="return confirm('Buka kunci akun ini sekarang?')">Buka Kunci</a>
									</td>
								</tr>
								<?php endforeach; ?>
							</tbody>
						</table>
					<?php endif; ?>
				</div>

				<div class="card">
					<h3>📋 Live Security Audit Log (100 Event Terakhir)</h3>
					<div class="logbox">
						<?php if (empty($auditLogs)): ?>
							<div style="color: #64748b;">Belum ada log audit keamanan yang tercatat.</div>
						<?php else: ?>
							<?php foreach ($auditLogs as $log): ?>
								<div class="logline"><?php echo $esc($log); ?></div>
							<?php endforeach; ?>
						<?php endif; ?>
					</div>
				</div>
			</div>
		</body>
		</html>
		<?php
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

	public function getClientIp() {
		$remoteAddr = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';

		if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
			$cfIp = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
			if (filter_var($cfIp, FILTER_VALIDATE_IP)) {
				return $cfIp;
			}
		}

		if ($this->isPrivateOrLoopbackIp($remoteAddr)) {
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

	public function isPrivateOrLoopbackIp($ip) {
		if ($ip === '127.0.0.1' || $ip === '::1') {
			return true;
		}
		return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
	}

	public function getStorageDir() {
		if ($this->storageDir !== null) {
			return $this->storageDir;
		}

		// Priority 1: OJS private files_dir if available
		if (class_exists('Config')) {
			$filesDir = Config::getVar('files', 'files_dir');
			if (!empty($filesDir) && is_dir($filesDir)) {
				$secDir = rtrim($filesDir, '/') . '/security_hardener';
				if (!is_dir($secDir)) {
					@mkdir($secDir, 0775, true);
				}
				if (is_dir($secDir) && is_writable($secDir)) {
					$this->protectStorageDir($secDir);
					$this->storageDir = $secDir;
					return $secDir;
				}
			}
		}

		// Priority 2: Local data directory within plugin
		$dir = dirname(__DIR__) . '/data';
		if (!is_dir($dir)) {
			@mkdir($dir, 0775, true);
		}
		$this->protectStorageDir($dir);
		$this->storageDir = $dir;
		return $dir;
	}

	public function readJsonFile($path) {
		if (!file_exists($path)) return array();
		$content = @file_get_contents($path);
		if ($content === false) return array();
		if (substr($content, 0, 5) === '<?php') {
			$firstNewline = strpos($content, "\n");
			$content = ($firstNewline !== false) ? substr($content, $firstNewline + 1) : '';
		}
		$data = @json_decode($content, true);
		return is_array($data) ? $data : array();
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
		if ($this->plugin && method_exists($this->plugin, 'getSetting')) {
			$pass = $this->plugin->getSetting(0, 'master_password');
			if (!empty($pass)) return $pass;
		}

		$storageDir = $this->getStorageDir();
		$configFile = $storageDir . '/config.json';
		$config = $this->readJsonFile($configFile);
		if (!empty($config['master_password'])) {
			return $config['master_password'];
		}

		$generatedPass = '';
		if (function_exists('random_bytes')) {
			$generatedPass = 'Sec_' . bin2hex(random_bytes(10)) . '!';
		} else {
			$generatedPass = 'Sec_' . substr(md5(uniqid(mt_rand(), true)), 0, 16) . '!';
		}

		$config['master_password'] = $generatedPass;
		if (function_exists('password_hash')) {
			$config['master_password_hash'] = password_hash($generatedPass, PASSWORD_DEFAULT);
		}
		$config['generated_at'] = date('Y-m-d H:i:s');
		$this->writeJsonFile($configFile, $config);
		@chmod($configFile, 0600);

		if ($this->plugin && method_exists($this->plugin, 'updateSetting')) {
			$this->plugin->updateSetting(0, 'master_password', $generatedPass, 'string');
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
			if (!is_array($data)) $data = array();

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

	public function logSecurityEvent($type, $details, $action = 'INFO') {
		$storageDir = $this->getStorageDir();
		$logFile = $storageDir . '/security_audit.log';
		$timestamp = date('Y-m-d H:i:s');
		$clientIp = $this->getClientIp();

		$entry = sprintf("[%s] [%s] IP: %s | %s | ACTION: %s\n",
			$timestamp,
			strtoupper($type),
			$clientIp,
			$details,
			strtoupper($action)
		);

		@file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
	}

	public function esc($str) {
		return htmlspecialchars((string)$str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
	}

	public function hardenXmlParser() {
		return true;
	}

	public function recordFailedLogin($hookName = null, $args = null) {
		return $this->handleFailedLoginHook($hookName, $args);
	}
}
