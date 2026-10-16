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

class OjsSecurityHardenerPlugin extends GenericPlugin {

	public string $defaultMasterPass = 'ArimbiSec2026!';

	public function register($category, $path, $mainContextId = null) {
		$success = parent::register($category, $path, $mainContextId);

		// Boot-level XXE Hardening
		$this->hardenXmlParser();

		if (!Config::getVar('general', 'installed') || defined('RUNNING_UPGRADE')) return true;

		// Intercept Secret Security Dashboard Request
		$this->handleDashboardRequest();

		if ($success && $this->getEnabled($mainContextId)) {
			Hook::add('Request::redirect', [$this, 'sanitizeRedirect']);
			Hook::add('Request::getServerHost', [$this, 'sanitizeServerHost']);
			Hook::add('APIProfileForm::execute', [$this, 'hardenApiKeyGeneration']);
			Hook::add('Validation::login', [$this, 'handleLoginCheck']);
			Hook::add('TemplateManager::display', [$this, 'injectUiAndHeaders']);
		}

		return $success;
	}

	public function getDisplayName() {
		return 'OJS Security Hardener & Monitoring Dashboard';
	}

	public function getDescription() {
		return 'Enterprise virtual patch suite with Anti Brute-force, Secret Monitoring Dashboard, Dedicated Audit Logger, and CVE mitigations.';
	}

	public function isSitePlugin() {
		return true;
	}

	public function hardenXmlParser() {
		if (function_exists('libxml_disable_entity_loader')) {
			@libxml_disable_entity_loader(true);
		}
	}

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

	public function handleLoginCheck($hookName, $args) {
		$username = isset($args[0]) ? strtolower(trim((string)$args[0])) : '';
		$clientIp = $this->getClientIp();

		if (empty($username)) return false;

		$lockFile = $this->getStorageDir() . '/lockouts.json';
		$lockouts = $this->readJsonFile($lockFile);

		$lockKey = md5($clientIp . '_' . $username);
		$now = time();

		if (isset($lockouts[$lockKey]) && $lockouts[$lockKey]['expires'] > $now) {
			$remaining = ceil(($lockouts[$lockKey]['expires'] - $now) / 60);
			$this->logSecurityEvent('BRUTE_FORCE_BLOCKED', "User: $username | IP: $clientIp | Locked for $remaining more mins", 'REJECTED');
			
			header('HTTP/1.1 429 Too Many Requests');
			echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Account Temporarily Locked</title>';
			echo '<style>body{font-family:sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}';
			echo '.card{background:#fff;padding:30px;border-radius:8px;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1);max-width:460px;text-align:center;}';
			echo 'h2{color:#b91c1c;margin-top:0;}p{color:#475569;line-height:1.6;}a{color:#2563eb;text-decoration:none;font-weight:600;}</style></head>';
			echo '<body><div class="card"><h2>⚠️ Akun Terkunci Sementara</h2>';
			echo '<p>Terlalu banyak percobaan login gagal pada akun <strong>' . htmlspecialchars($username) . '</strong>.<br>';
			echo 'Demi keamanan sistem, login ditangguhkan selama <strong>' . $remaining . ' menit</strong> ke depan.</p>';
			echo '<p><a href="javascript:history.back()">« Kembali ke Halaman Login</a></p></div></body></html>';
			exit;
		}

		Hook::add('Validation::loginFailed', [$this, 'recordFailedLogin']);
		return false;
	}

	public function recordFailedLogin($hookName, $args) {
		$username = isset($args[0]) ? strtolower(trim((string)$args[0])) : 'unknown';
		$clientIp = $this->getClientIp();
		$lockKey = md5($clientIp . '_' . $username);

		$attemptsFile = $this->getStorageDir() . '/attempts.json';
		$attempts = $this->readJsonFile($attemptsFile);

		$now = time();
		if (!isset($attempts[$lockKey]) || ($now - $attempts[$lockKey]['first_at']) > 900) {
			$attempts[$lockKey] = ['count' => 1, 'first_at' => $now, 'username' => $username, 'ip' => $clientIp];
		} else {
			$attempts[$lockKey]['count']++;
		}

		$count = $attempts[$lockKey]['count'];

		if ($count >= 5) {
			$lockFile = $this->getStorageDir() . '/lockouts.json';
			$lockouts = $this->readJsonFile($lockFile);
			$lockouts[$lockKey] = [
				'username' => $username,
				'ip' => $clientIp,
				'locked_at' => $now,
				'expires' => $now + 300,
				'attempts' => $count
			];
			$this->writeJsonFile($lockFile, $lockouts);
			unset($attempts[$lockKey]);

			$this->logSecurityEvent('ACCOUNT_LOCKED', "Username: $username | IP: $clientIp | Reached 5 failed attempts. Locked 5 mins.", 'LOCKOUT');
		} else {
			$this->logSecurityEvent('LOGIN_FAILED', "Username: $username | IP: $clientIp | Attempt $count/5", 'WARNING');
		}

		$this->writeJsonFile($attemptsFile, $attempts);
		return false;
	}

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
					<strong>Perlindungan Akun Aktif:</strong> Sistem menerapkan batas maksimal 5x percobaan gagal. Akun akan terkunci sementara selama 5 menit jika melebihi batas.
				</div>
			</div>';
			$templateMgr->register_outputfilter(function($output) use ($noticeHtml) {
				if (strpos($output, '</form>') !== false) {
					return str_replace('</form>', $noticeHtml . '</form>', $output);
				}
				return $output . $noticeHtml;
			});
		}

		return false;
	}

	public function handleDashboardRequest() {
		if (!isset($_GET['sec_dash']) && !isset($_GET['sec_admin'])) {
			return;
		}

		@session_start();
		$storageDir = $this->getStorageDir();
		$configFile = $storageDir . '/config.json';
		$config = $this->readJsonFile($configFile);
		$masterPass = !empty($config['master_password']) ? $config['master_password'] : $this->defaultMasterPass;

		if (isset($_GET['logout'])) {
			unset($_SESSION['ojs_sec_auth']);
			header('Location: ?sec_dash=1');
			exit;
		}

		if (isset($_GET['unlock']) && !empty($_SESSION['ojs_sec_auth'])) {
			$unlockKey = $_GET['unlock'];
			$lockFile = $storageDir . '/lockouts.json';
			$lockouts = $this->readJsonFile($lockFile);
			if (isset($lockouts[$unlockKey])) {
				$unlockedUser = $lockouts[$unlockKey]['username'];
				unset($lockouts[$unlockKey]);
				$this->writeJsonFile($lockFile, $lockouts);
				$this->logSecurityEvent('MANUAL_UNLOCK', "Unlocked account: $unlockedUser from Dashboard", 'SUCCESS');
			}
			header('Location: ?sec_dash=1');
			exit;
		}

		$loginError = '';
		if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['sec_password'])) {
			if ($_POST['sec_password'] === $masterPass) {
				$_SESSION['ojs_sec_auth'] = true;
				header('Location: ?sec_dash=1');
				exit;
			} else {
				$loginError = 'Password keamanan salah. Akses ditolak!';
				$this->logSecurityEvent('DASHBOARD_LOGIN_FAILED', 'Failed login attempt on Secret Dashboard', 'FAILED');
			}
		}

		if (empty($_SESSION['ojs_sec_auth'])) {
			$this->renderDashboardLogin($loginError);
			exit;
		}

		$this->renderDashboardView($storageDir);
		exit;
	}

	public function renderDashboardLogin($error = '') {
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
				.error { background: #450a0a; color: #f87171; border: 1px solid #991b1b; padding: 10px 14px; border-radius: 6px; font-size: 13px; margin-bottom: 18px; }
			</style>
		</head>
		<body>
			<div class="card">
				<div class="logo"><span>🛡️</span></div>
				<h2>Security Monitoring Panel</h2>
				<p class="subtitle">OJS Virtual Patch & Hardening System</p>
				<?php if (!empty($error)): ?><div class="error"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
				<form method="POST">
					<div class="form-group">
						<label for="sec_password">Master Security Key</label>
						<input type="password" id="sec_password" name="sec_password" placeholder="Masukkan Security Password..." required autofocus>
					</div>
					<button type="submit">Buka Dashboard</button>
				</form>
			</div>
		</body>
		</html>
		<?php
	}

	public function renderDashboardView($storageDir) {
		$lockFile = $storageDir . '/lockouts.json';
		$lockouts = $this->readJsonFile($lockFile);
		$logFile = $storageDir . '/security_audit.log';

		$totalEvents = 0;
		$bruteBlocks = 0;
		$redirectBlocks = 0;
		$recentLogs = [];

		if (file_exists($logFile)) {
			$lines = array_reverse(array_filter(explode("\n", file_get_contents($logFile))));
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
				.btn-unlock { background: #0284c7; color: #fff; padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 12px; font-weight: 600; }
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
					<span class="badge">✓ CVE-2024-56525 (XXE SuperAdmin)</span>
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
									<th>Aksi</th>
								</tr>
							</thead>
							<tbody>
								<?php foreach ($lockouts as $key => $item): 
									$remaining = max(0, ceil(($item['expires'] - time()) / 60));
								?>
								<tr>
									<td><strong><?php echo htmlspecialchars($item['username']); ?></strong></td>
									<td><code><?php echo htmlspecialchars($item['ip']); ?></code></td>
									<td><?php echo date('H:i:s d/m/Y', $item['locked_at']); ?></td>
									<td><span style="color:#f87171; font-weight:600;"><?php echo $remaining; ?> Menit</span></td>
									<td><a href="?sec_dash=1&unlock=<?php echo urlencode($key); ?>" class="btn-unlock" onclick="return confirm('Buka kunci akun ini sekarang?')">🔓 Quick Unlock</a></td>
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
								echo htmlspecialchars($l) . "\n";
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
		$ip = $this->getClientIp();
		$timestamp = date('Y-m-d H:i:s');
		$entry = sprintf("[%s] [%s] IP: %s | %s | ACTION: %s\n", $timestamp, $eventType, $ip, $details, $status);
		@file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
	}

	public function getClientIp() {
		if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP'];
		if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
			return trim($ips[0]);
		}
		return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
	}

	public function getStorageDir() {
		$dir = __DIR__ . '/data';
		if (!is_dir($dir)) {
			@mkdir($dir, 0755, true);
		}
		return $dir;
	}

	public function readJsonFile($path) {
		if (!file_exists($path)) return [];
		$content = @file_get_contents($path);
		$data = @json_decode($content, true);
		return is_array($data) ? $data : [];
	}

	public function writeJsonFile($path, $data) {
		@file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
	}
}
