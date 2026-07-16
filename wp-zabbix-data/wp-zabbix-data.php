<?php
/**
 * Plugin Name:         WP Zabbix Monitor Endpoint
 * Plugin URI:          https://moesgaards.dk/
 * Description:         Adds a secure WP-Admin settings page with metric visibility controls and exposes a secure REST API endpoint for Zabbix monitoring. Includes self-clearing error logs, memory limits in bits, unique visitor tracking, database bloat measurements, and WooCommerce order health.
 * Version:             1.6.0
 * Author:              Morten Moesgaard  
 * Author URI:          https://moesgaards.dk/
 * License:             GPLv2 or later
 * Text Domain:         wp-zabbix-data
 */

// Exit if accessed directly to prevent unauthorized file execution
if (!defined('ABSPATH')) {
  exit;
}

/**
 * =========================================================================
 * 1. REGISTER THE PRIVATE ERROR LOGGER & WRITER
 * =========================================================================
 */
class Zabbix_Custom_Logger
{

  private static $log_file_path = '';

  public static function init()
  {
    self::$log_file_path = self::get_secure_log_path();

    // Catch runtime warnings, notices, and errors
    set_error_handler(array(__CLASS__, 'handle_standard_errors'));

    // Catch fatal crash errors right before PHP halts
    register_shutdown_function(array(__CLASS__, 'handle_fatal_errors'));
  }

  /**
   * Generates a unique, hidden log path inside WP Uploads.
   * The file is named with a hash based on your DB secret to prevent guessing.
   */
  private static function get_secure_log_path()
  {
    $upload_dir = wp_upload_dir();
    $target_dir = $upload_dir['basedir'] . '/zabbix-monitor-logs';

    if (!file_exists($target_dir)) {
      wp_mkdir_p($target_dir);
      // Write an index.php and .htaccess file to block web access
      file_put_contents($target_dir . '/index.php', '<?php // Silence');
      file_put_contents($target_dir . '/.htaccess', 'deny from all');
    }

    // Generate a filename unique to this site's secret salt
    $salt = defined('AUTH_KEY') ? AUTH_KEY : 'zabbix_fallback_salt';
    $filename = 'log_' . hash_hmac('sha256', 'zabbix_errors', $salt) . '.log.php';

    return $target_dir . '/' . $filename;
  }

  /**
   * Appends a clean error line to our private file.
   */
  public static function write_to_log($level, $message, $file, $line)
  {
    $timestamp = current_time('mysql');
    // If the file doesn't exist or is empty, write a PHP exit header first 
    // to prevent direct browser execution of the log file if accessed.
    $prepend_security = '';
    if (!file_exists(self::$log_file_path) || filesize(self::$log_file_path) === 0) {
      $prepend_security = "<?php exit; ?>\n";
    }

    $log_entry = sprintf(
      "[%s] %s: %s in %s on line %d\n",
      $timestamp,
      $level,
      $message,
      $file,
      $line
    );

    file_put_contents(self::$log_file_path, $prepend_security . $log_entry, FILE_APPEND | LOCK_EX);
  }

  /**
   * Handler for Warnings, Notices, and Standard PHP errors.
   */

  public static function handle_standard_errors($errno, $errstr, $errfile, $errline)
  {
    // Ignore errors suppressed with the @ operator
    if (!(error_reporting() & $errno)) {
      return false;
    }

    $levels = array(
      E_WARNING => 'Warning',
      E_NOTICE => 'Notice',
      E_USER_ERROR => 'User Error',
      E_USER_WARNING => 'User Warning',
      E_USER_NOTICE => 'User Notice',
      E_DEPRECATED => 'Deprecated',
      E_USER_DEPRECATED => 'User Deprecated'
    );

    $level_name = isset($levels[$errno]) ? $levels[$errno] : 'Unknown Error';
    self::write_to_log($level_name, $errstr, $errfile, $errline);

    return false; // Keep passing the error to native WP handler/display
  }

  /**
   * Handler for Fatal script-terminating crashes.
   */
  public static function handle_fatal_errors()
  {
    $error = error_get_last();
    if ($error && in_array($error['type'], array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR))) {
      self::write_to_log('FATAL ERROR', $error['message'], $error['file'], $error['line']);
    }
  }

  /**
   * Reads, cleans, and returns the log file entries.
   */
  public static function read_and_clear_logs()
  {
    $log_file = self::get_secure_log_path();

    if (!file_exists($log_file) || filesize($log_file) === 0) {
      return array();
    }

    $lines = file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

    //Remove our security header from the array output
    if (!empty($lines) && strpos($lines[0], '<?php') !== false) {
      array_shift($lines);
    }

    // --- CLEAR FILE ONCE READ ---
    // Overwrite the file with just the security header (meaning its empty of logs again)
    file_put_contents($log_file, "<?php exit; ?>\n", LOCK_EX);

    return $lines;
  }
}

// Fire up the custom logging mechanism right away!
Zabbix_Custom_Logger::init();


/**
 * =========================================================================
 * 2. UNIQUE VISITOR MONITORING MECHANISM & DB INTEGRATION
 * =========================================================================
 */

// Create the tracking DB Table on Activation
register_activation_hook(__FILE__, 'zabbix_visitor_tracker_activate');
function zabbix_visitor_tracker_activate()
{
  global $wpdb;
  $table_name = $wpdb->prefix . 'zabbix_visitor_log';
  $charset_collate = $wpdb->get_charset_collate();

  $sql = "CREATE TABLE $table_name (
    id bigint(20) NOT NULL AUTO_INCREMENT,
    visitor_hash varchar(32) NOT NULL,
    visit_date date NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY visitor_date (visitor_hash, visit_date)
  ) $charset_collate;";

  require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
  dbDelta($sql);

  // Setup daily pruning cron
  if (!wp_next_scheduled('zabbix_visitor_cleanup_event')) {
    wp_schedule_event(time(), 'daily', 'zabbix_visitor_cleanup_event');
  }
}

// Clear Cron schedules on deactivation
register_deactivation_hook(__FILE__, 'zabbix_visitor_tracker_deactivate');
function zabbix_visitor_tracker_deactivate()
{
  wp_clear_scheduled_hook('zabbix_visitor_cleanup_event');
}

// Perform DB Pruning to keep size small (deletes records > 90 days)
add_action('zabbix_visitor_cleanup_event', 'zabbix_visitor_db_prune');
function zabbix_visitor_db_prune()
{
  global $wpdb;
  $table_name = $wpdb->prefix . 'zabbix_visitor_log';
  $wpdb->query("DELETE FROM $table_name WHERE visit_date < DATE_SUB(NOW(), INTERVAL 90 DAY)"); } 
/** 
 * Get IP helper to extract real users even through Reverse Proxies (Cloudflare/Suri/Nginx) 
 * */ 
function zabbix_visitor_get_ip() { 
  if (!empty($_SERVER['HTTP_CLIENT_IP'])) { return $_SERVER['HTTP_CLIENT_IP']; } elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { 
    $ips=explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    return trim($ips[0]); 
  }
  return $_SERVER['REMOTE_ADDR']; 
} 
/**
 *  Capture unique visitor frontend requests (anonymous  hashing, no plain IP database storage) 
 **/ 
add_action('wp', 'zabbix_track_visitor_hit' ); 
function zabbix_track_visitor_hit() { 
  //Check first if visitor tracking metric is enabled in settings before tracking

  $enabled_metrics=get_option('zabbix_selected_metrics', zabbix_get_default_metrics()); 
  if (!is_array($enabled_metrics) || !in_array('visitors', $enabled_metrics)) { return; } 
  // Avoid logging REST, AJAX, WP-Cron, or Administrative sessions 
  if (is_admin() || wp_doing_ajax() || wp_doing_cron() || (defined('REST_REQUEST')  && REST_REQUEST)) { 
    return; 
  } 
  // Skip tracking logged-in Administrators to keep clean production analytics 
  if (current_user_can('manage_options')) { 
    return; 
  } 
  global $wpdb; 
  $table_name=$wpdb->prefix . 'zabbix_visitor_log';
  $ip = zabbix_visitor_get_ip();
  $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
  $today = current_time('Y-m-d');

  // Build a private hash using a salt changing daily to prevent reverse lookup of IPs
  $daily_salt = wp_salt() . $today;
  $visitor_hash = md5($daily_salt . $ip . $user_agent);

  // INSERT IGNORE handles the UNIQUE constraint index block silently
  $wpdb->query(
    $wpdb->prepare(
      "INSERT IGNORE INTO $table_name (visitor_hash, visit_date) VALUES (%s, %s)",
      $visitor_hash,
      $today
    )
  );
}

/**
 * Parses PHP memory notation shorthand to raw bits.
 */
function zabbix_convert_memory_limit_to_bits($memory_limit)
{
  $memory_limit = trim($memory_limit);

  // -1 represents unlimited memory setting
  if ($memory_limit === '-1' || empty($memory_limit)) {
    return -1;
  }

  $numeric_value = (float) $memory_limit;
  $unit = strtolower(substr($memory_limit, -1));

  switch ($unit) {
  case 'g':
    $numeric_value *= 1024;
  case 'm':
    $numeric_value *= 1024;
  case 'k':
    $numeric_value *= 1024;
  }

  // Bytes to bits (value * 8)
  return (int) ($numeric_value * 8);
}

/**
 * Helper to define the list of toggleable monitor blocks
 */
function zabbix_get_metric_options()
{
  return array(
    'core_versions' => 'WordPress & PHP Environment Info (Versions, Memory limit)',
    'db_stats' => 'Database Metrics (Database size, Autoload values size)',
    'db_health' => 'Database Bloat & Health (Total Overhead space, Expired Transients count)',
    'cron_health' => 'Cron Health Checks (Check if WP-Cron tasks are jammed)',
    'cpu_load' => 'System Resource Load (1, 5, and 15-minute load averages)',
    'file_changes' => 'Integrity Status (Scanned modified files tracker)',
    'security_check' => 'Security Check (Count of Administrator Accounts)',
    'active_plugins' => 'Installed Plugins Inventory List',
    'woocommerce' => 'WooCommerce Alert Monitoring (Failed/Pending orders in the last 24h)',
    'error_logs' => 'Recent Runtime Logs (Fetch & auto-clear PHP warnings/errors)',
    'visitors' => 'Privacy-Safe Unique Visitors (Tracks daily uniques & 30-day stats)'
  );
}

/**
 * Helper to define what's checked by default on new installations
 */
function zabbix_get_default_metrics()
{
  return array_keys(zabbix_get_metric_options());
}


/**
 * =========================================================================
 * 3. CREATE THE ADMIN MENU ITEM
 * =========================================================================
 */
add_action('admin_menu', 'zabbix_monitoring_menu');
function zabbix_monitoring_menu()
{
  add_options_page(
    'Zabbix Monitoring Settings',
    'Zabbix Monitoring',
    'manage_options',
    'zabbix-monitoring-settings',
    'zabbix_monitoring_settings_page'
  );
}

/**
 * =========================================================================
 * 4. REGISTER SETTINGS & FIELDS
 * =========================================================================
 */
add_action('admin_init', 'zabbix_monitoring_settings_init');
function zabbix_monitoring_settings_init()
{
  register_setting(
    'zabbix_settings_group',
    'zabbix_secure_token',
    array('sanitize_callback' => 'hash_zabbix_token_on_save')
  );

  // Register our metrics visibility setting
  register_setting(
    'zabbix_settings_group',
    'zabbix_selected_metrics',
    array(
      'type' => 'array',
      'sanitize_callback' => 'zabbix_sanitize_metrics_selection',
      'default' => zabbix_get_default_metrics()
    )
  );

  add_settings_section(
    'zabbix_main_section',
    'Zabbix API Configuration',
    __return_false(),
    'zabbix-monitoring-settings'
  );

  add_settings_field(
    'zabbix_secure_token_field',
    'Zabbix Secret Token',
    'zabbix_token_field_renderer',
    'zabbix-monitoring-settings',
    'zabbix_main_section'
  );

  add_settings_field(
    'zabbix_selected_metrics_field',
    'Exposed Metrics Settings',
    'zabbix_metrics_checkboxes_renderer',
    'zabbix-monitoring-settings',
    'zabbix_main_section'
  );
}

function hash_zabbix_token_on_save($input)
{
  $input = trim($input);
  if ($input === '********') {
    return get_option('zabbix_secure_token');
  }
  if (empty($input)) {
    return '';
  }
  if (strpos($input, '$P$') === 0 || strpos($input, '$2y$') === 0) {
    return $input;
  }
  return wp_hash_password($input);
}

/**
 * Ensures only valid metric keys are saved to the database.
 */
function zabbix_sanitize_metrics_selection($input)
{
  if (!is_array($input)) {
    return array();
  }
  $valid_options = array_keys(zabbix_get_metric_options());
  return array_intersect($input, $valid_options);
}

function zabbix_token_field_renderer()
{
  $value = get_option('zabbix_secure_token');
  if (!empty($value)) {
    echo '<input type="password" name="zabbix_secure_token" value="********" onfocus="this.value=\'\'"
      class="regular-text" />';
    echo '<p class="description">A secure token is already saved. Type a new one to overwrite it.</p>';
  } else {
    echo '<input type="password" name="zabbix_secure_token" value="" class="regular-text"
      placeholder="Enter plaintext token here" />';
    echo '<p class="description">This will be securely hashed upon saving.</p>';
  }
}

/**
 * Render checkboxes dynamically for the metrics UI selector
 */
function zabbix_metrics_checkboxes_renderer()
{
  $current_selections = get_option('zabbix_selected_metrics', zabbix_get_default_metrics());
  if (!is_array($current_selections)) {
    $current_selections = array();
  }

  $options = zabbix_get_metric_options();

  echo '<fieldset style="margin-top: 5px;">';
  echo '<legend class="screen-reader-text"><span>Exposed Metrics Settings</span></legend>';
  echo '<p class="description" style="margin-bottom: 12px;">Select what telemetry blocks should be returned when
    Zabbix fetches the REST API endpoint:</p>';

  foreach ($options as $key => $label) {
    $checked = in_array($key, $current_selections) ? 'checked="checked"' : '';
    echo sprintf(
      '<label style="display: block; margin-bottom: 8px; font-weight: 500;">' .
      '<input type="checkbox" name="zabbix_selected_metrics[]" value="%s" %s style="margin-right: 8px;" /> %s' .
      '</label>',
      esc_attr($key),
      $checked,
      esc_html($label)
    );
  }
  echo '</fieldset>';
}

function zabbix_monitoring_settings_page()
{
?>
    <div class="wrap">
        <h1>WordPress Zabbix Monitoring</h1>
        <form action="options.php" method="POST">
<?php
  settings_fields('zabbix_settings_group');
  do_settings_sections('zabbix-monitoring-settings');
  submit_button('Save Zabbix Configuration');
?>
        </form>
    </div>
<?php
}

/**
 * =========================================================================
 * 5. REGISTER THE REST API ENDPOINT & VERIFICATION
 * =========================================================================
 */
add_action('rest_api_init', function () {
  register_rest_route('zabbix/v1', '/stats', array(
    'methods' => 'GET',
    'callback' => 'get_wordpress_zabbix_stats',
    'permission_callback' => 'verify_zabbix_db_token',
  ));
});

function verify_zabbix_db_token($request)
{
  $stored_hash = get_option('zabbix_secure_token');
  $provided_token = $request->get_header('X-Zabbix-Token');

  if (!$stored_hash || !$provided_token) {
    return false;
  }

  return wp_check_password($provided_token, $stored_hash);
}

// Gather stats payload for Zabbix
// Gather stats payload optimized for Zabbix LLD & Dependent Items
function get_wordpress_zabbix_stats()
{
  global $wp_version, $wpdb;

  // Load metrics options saved by admin installer
  $enabled_metrics = get_option('zabbix_selected_metrics', zabbix_get_default_metrics());
  if (!is_array($enabled_metrics)) {
    $enabled_metrics = array();
  }

  // Initialize flat metrics list & discoverable lists
  $metrics = array(
    'status' => 1 // Status represented as integer (1 = healthy) for triggers
  );
  $plugins_discovery = array();

  // 1. Core Environment Metrics Block
  if (in_array('core_versions', $enabled_metrics)) {
    $php_memory_limit = ini_get('memory_limit');
    $metrics['wp_version'] = $wp_version;
    $metrics['php_version'] = phpversion();
    $metrics['memory_peak_b'] = memory_get_peak_usage(true);
    $metrics['memory_limit_bits'] = zabbix_convert_memory_limit_to_bits($php_memory_limit);
  }

  // 2. Database Space Block
  if (in_array('db_stats', $enabled_metrics)) {
    $db_size = $wpdb->get_var("SELECT SUM(data_length + index_length) FROM information_schema.TABLES WHERE table_schema = '" . DB_NAME . "'");
    $autoload_size = $wpdb->get_var("SELECT SUM(LENGTH(option_value)) FROM $wpdb->options WHERE autoload = 'yes'");

    $metrics['database_size_b'] = intval($db_size);
    $metrics['autoload_size_b'] = intval($autoload_size);
  }

  // 3. Database Health (Overhead and Expired Transients)
  if (in_array('db_health', $enabled_metrics)) {
    $db_overhead = $wpdb->get_var("SELECT SUM(data_free) FROM information_schema.TABLES WHERE table_schema = '" . DB_NAME . "'");

    $now = time();
    $expired_transients = $wpdb->get_var(
      $wpdb->prepare(
        "SELECT COUNT(*) FROM $wpdb->options 
        WHERE option_name LIKE '\_transient\_timeout\_%' 
        AND option_value < %d",
    $now
      )
    );

    $metrics['database_overhead_b'] = intval($db_overhead);
    $metrics['expired_transients_count'] = intval($expired_transients);
  }

  // 4. WP-Cron Status Block
  if (in_array('cron_health', $enabled_metrics)) {
    $cron_warning = 0;
    $crons = _get_cron_array();
    if (!empty($crons)) {
      $first_task_time = key($crons);
      if ($first_task_time < (time() - 1800)) {
        $cron_warning = 1;
      }
    }
    $metrics['cron_is_jammed'] = $cron_warning;
  }

  // 5. Server Resource Load Block
  if (in_array('cpu_load', $enabled_metrics)) {
    $cpu_load = function_exists('sys_getloadavg') ? sys_getloadavg() : array(0, 0, 0);
    $metrics['cpu_load_1min'] = $cpu_load[0];
    $metrics['cpu_load_5min'] = $cpu_load[1];
    $metrics['cpu_load_15min'] = $cpu_load[2];
  }

  // 6. File Integrity Changes Block
  if (in_array('file_changes', $enabled_metrics)) {
    $file_changes_detected = 0;
    if (class_exists('MFM_Scan_Results')) {
      $file_changes_detected = get_option('mfm_file_changes_count', 0);
    }
    $metrics['file_changes_detected'] = intval($file_changes_detected);
  }

  // 7. Security Account Counts
  if (in_array('security_check', $enabled_metrics)) {
    $metrics['admin_users_count'] = count(get_users(array('role' => 'administrator')));
  }

  // 8. Installed Plugins Block (Optimized for Zabbix Native LLD & Simple Dependent Items)
  if (in_array('active_plugins', $enabled_metrics)) {
    if (!function_exists('get_plugins')) {
      require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $all_plugins = get_plugins();

    $plugin_versions = array();
    foreach ($all_plugins as $plugin_path => $plugin_data) {
      $name = $plugin_data['Name'];

      // 1. Discovery Array: Just lists the names for Zabbix LLD to find
      $plugins_discovery[] = array(
        '{#PLUGIN_NAME}' => $name
      );

      // 2. Simple flat lookup array: key is the plugin name, value is the version
      // e.g., "WooCommerce": "8.4.0"
      $plugin_versions[$name] = $plugin_data['Version'];
    }

    // Add the flat key-value list to our main metrics payload
    $metrics['plugins'] = $plugin_versions;
  }

  // 9. WooCommerce Alert Monitoring (Conditional check if active)
  if (in_array('woocommerce', $enabled_metrics)) {
    if (class_exists('WooCommerce')) {
      $one_day_ago = date('Y-m-d H:i:s', time() - 86400);

      $failed_orders = count(wc_get_orders(array(
        'status' => 'failed',
        'date_created' => '>' . $one_day_ago,
        'limit' => -1,
        'return' => 'ids',
      )));

      $pending_orders = count(wc_get_orders(array(
        'status' => 'pending',
        'date_created' => '>' . $one_day_ago,
        'limit' => -1,
        'return' => 'ids',
      )));

      $metrics['woocommerce_active'] = 1;
      $metrics['woocommerce_failed_orders_24h'] = $failed_orders;
      $metrics['woocommerce_pending_orders_24h'] = $pending_orders;
    } else {
      $metrics['woocommerce_active'] = 0;
      $metrics['woocommerce_failed_orders_24h'] = 0;
      $metrics['woocommerce_pending_orders_24h'] = 0;
    }
  }

  // 10. Error Logger Block (Fetch AND auto-clear PHP logs)
  if (in_array('error_logs', $enabled_metrics)) {
    $recent_errors = Zabbix_Custom_Logger::read_and_clear_logs();
    $metrics['recent_errors_count'] = count($recent_errors);
    // Convert to comma-separated string for simple Zabbix text item
    $metrics['recent_errors_log'] = !empty($recent_errors) ? implode("\n", $recent_errors) : "No recent errors";
  }

  // 11. Unique Visitors Block
  if (in_array('visitors', $enabled_metrics)) {
    $visitor_table = $wpdb->prefix . 'zabbix_visitor_log';
    $today = current_time('Y-m-d');

    $uniques_today = $wpdb->get_var(
      $wpdb->prepare(
        "SELECT COUNT(id) FROM $visitor_table WHERE visit_date = %s",
        $today
      )
    );

    $uniques_30_days = $wpdb->get_var(
      $wpdb->prepare(
        "SELECT COUNT(id) FROM $visitor_table WHERE visit_date >= DATE_SUB(%s, INTERVAL 30 DAY)",
        $today
      )
    );

    $metrics['unique_visitors_today'] = intval($uniques_today);
    $metrics['unique_visitors_30_days'] = intval($uniques_30_days);
  }

  // Return structural JSON optimal for Zabbix Template integration
  return new WP_REST_Response(array(
    'metrics' => $metrics,
    'plugins_discovery' => $plugins_discovery
  ), 200);
}
