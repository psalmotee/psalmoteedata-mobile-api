<?php
/**
 * Plugin Name: PsalmoteeData Mobile API
 * Description: Secure mobile authentication endpoints for the PsalmoteeData app.
 * Version: 0.2.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Psalmotee-Tech
 * Text Domain: psalmoteedata-mobile-api
 */

if (!defined('ABSPATH')) {
    exit;
}

final class PsalmoteeData_Mobile_API {

    const VERSION = '0.2.0';
    const REST_NAMESPACE = 'psalmoteedata-mobile/v1';

    // Maximum lifetime of an authentication token.
    const TOKEN_LIFETIME = 30 * DAY_IN_SECONDS;

    // Session expires after five minutes without authenticated activity.
    const INACTIVITY_TIMEOUT = 5 * MINUTE_IN_SECONDS;

    // Login protection.
    const LOGIN_LIMIT = 10;
    const LOGIN_WINDOW = 15 * MINUTE_IN_SECONDS;

    private static $instance = null;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct() {
        add_action('rest_api_init', array($this, 'register_routes'));
    }

    /**
     * Create the authentication token database table.
     */
    public static function activate() {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table_name = $wpdb->prefix . 'psalmoteedata_mobile_tokens';

        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table_name} (
            token_hash char(64) NOT NULL,
            user_id bigint(20) unsigned NOT NULL,
            created_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            last_used_at datetime NULL,
            PRIMARY KEY  (token_hash),
            KEY user_id (user_id),
            KEY expires_at (expires_at),
            KEY last_used_at (last_used_at)
        ) {$charset_collate};";

        dbDelta($sql);
    }

    /**
     * Register REST API endpoints.
     */
    public function register_routes() {

        // Login.
        register_rest_route(self::REST_NAMESPACE, '/login', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'login'),
            'permission_callback' => '__return_true',
        ));

        // Current authenticated user.
        register_rest_route(self::REST_NAMESPACE, '/me', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_me'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));

        // Heartbeat.
        register_rest_route(self::REST_NAMESPACE, '/heartbeat', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'heartbeat'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));

        // Logout.
        register_rest_route(self::REST_NAMESPACE, '/logout', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'logout'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));
    }

    /**
     * Standard API response.
     */
    private function response($data, $status = 200) {

        $response = new WP_REST_Response($data, $status);

        $response->header(
            'Cache-Control',
            'no-store, no-cache, must-revalidate, max-age=0'
        );

        $response->header('Pragma', 'no-cache');

        return $response;
    }

    /**
     * Get authentication token table.
     */
    private function token_table() {
        global $wpdb;

        return $wpdb->prefix . 'psalmoteedata_mobile_tokens';
    }

    /**
     * Get client IP address.
     */
    private function client_ip() {

        // Do not trust forwarded headers.
        return isset($_SERVER['REMOTE_ADDR'])
            ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']))
            : 'unknown';
    }

    /**
     * Generate login rate-limit key.
     */
    private function login_rate_key($identifier) {

        return 'ptd_mobile_login_' . hash(
            'sha256',
            $this->client_ip() . '|' . strtolower($identifier)
        );
    }

    /**
     * Check login rate limit.
     */
    private function login_rate_limited($identifier) {

        $key = $this->login_rate_key($identifier);

        $attempts = (int) get_transient($key);

        if ($attempts >= self::LOGIN_LIMIT) {
            return true;
        }

        set_transient(
            $key,
            $attempts + 1,
            self::LOGIN_WINDOW
        );

        return false;
    }

    /**
     * Clear login rate limit after successful login.
     */
    private function clear_login_rate_limit($identifier) {

        delete_transient(
            $this->login_rate_key($identifier)
        );
    }

    /**
     * Validate VTU Press account.
     */
    private function validate_vtupress_account($wp_user) {

        global $wpdb;

        if (!class_exists('Users')) {

            return new WP_Error(
                'vtupress_unavailable',
                'VTU Press account services are not available.',
                array('status' => 503)
            );
        }

        $users_api = new Users();

        $vt_user = $users_api->getUser(
            $wp_user->ID,
            true,
            true
        );

        if (!$vt_user) {

            return new WP_Error(
                'account_not_synced',
                'This account is not synchronized with VTU Press. Please contact support.',
                array('status' => 403)
            );
        }

        $settings_table = $wpdb->prefix . 'vtupress_general_settings';

        $settings = $wpdb->get_row(
            "SELECT * FROM {$settings_table} ORDER BY id ASC LIMIT 1",
            ARRAY_A
        );

        if (empty($settings)) {

            return new WP_Error(
                'account_settings_unavailable',
                'Account settings could not be loaded.',
                array('status' => 503)
            );
        }

        if (
            isset($settings['enable_email_verification']) &&
            $settings['enable_email_verification'] === 'yes' &&
            (
                !isset($vt_user['email_verified']) ||
                $vt_user['email_verified'] !== 'yes'
            )
        ) {

            return new WP_Error(
                'email_not_verified',
                'Please verify your email address before signing in.',
                array('status' => 403)
            );
        }

        return true;
    }

    /**
     * Login endpoint.
     */
    public function login(WP_REST_Request $request) {

        $identifier = trim(
            (string) $request->get_param('username')
        );

        $password = (string) $request->get_param('password');

        if ($identifier === '' || $password === '') {

            return $this->response(array(
                'success' => false,
                'message' => 'Username/email and password are required.',
            ), 400);
        }

        if ($this->login_rate_limited($identifier)) {

            return $this->response(array(
                'success' => false,
                'message' => 'Too many login attempts. Please wait and try again.',
            ), 429);
        }

        if (is_email($identifier)) {

            $wp_user = get_user_by(
                'email',
                sanitize_email($identifier)
            );

        } else {

            $wp_user = get_user_by(
                'login',
                sanitize_user($identifier)
            );
        }

        if (!$wp_user) {

            return $this->response(array(
                'success' => false,
                'message' => 'Invalid login details.',
            ), 401);
        }

        // Validate VTU Press account.
        $account_check = $this->validate_vtupress_account($wp_user);

        if (is_wp_error($account_check)) {

            $data = $account_check->get_error_data();

            $status = is_array($data) && isset($data['status'])
                ? (int) $data['status']
                : 403;

            return $this->response(array(
                'success' => false,
                'message' => $account_check->get_error_message(),
                'code' => $account_check->get_error_code(),
            ), $status);
        }

        // Verify password.
        $authenticated_user = wp_authenticate(
            $wp_user->user_login,
            $password
        );

        if (is_wp_error($authenticated_user)) {

            return $this->response(array(
                'success' => false,
                'message' => 'Invalid login details.',
            ), 401);
        }

        // Generate secure random token.
        try {

            $plain_token = bin2hex(random_bytes(32));

        } catch (Exception $exception) {

            return $this->response(array(
                'success' => false,
                'message' => 'Unable to create a secure session. Please try again.',
            ), 500);
        }

        $now = time();

        $created_at = gmdate(
            'Y-m-d H:i:s',
            $now
        );

        $expires_at = gmdate(
            'Y-m-d H:i:s',
            $now + self::TOKEN_LIFETIME
        );

        global $wpdb;

        $inserted = $wpdb->insert(
            $this->token_table(),
            array(
                'token_hash' => hash('sha256', $plain_token),
                'user_id' => (int) $authenticated_user->ID,
                'created_at' => $created_at,
                'expires_at' => $expires_at,
                'last_used_at' => $created_at,
            ),
            array('%s', '%d', '%s', '%s', '%s')
        );

        if (!$inserted) {

            return $this->response(array(
                'success' => false,
                'message' => 'Unable to create your session. Please try again.',
            ), 500);
        }

        $this->clear_login_rate_limit($identifier);

        return $this->response(array(
            'success' => true,
            'message' => 'Login successful.',
            'token_type' => 'Bearer',
            'access_token' => $plain_token,
            'expires_at' => gmdate(
                'c',
                $now + self::TOKEN_LIFETIME
            ),
            'user' => $this->public_user_data($authenticated_user),
        ));
    }

    /**
     * Public user information.
     */
    private function public_user_data($user) {

        return array(
            'id' => (int) $user->ID,
            'username' => (string) $user->user_login,
            'display_name' => (string) $user->display_name,
            'email' => (string) $user->user_email,
            'first_name' => (string) get_user_meta(
                $user->ID,
                'first_name',
                true
            ),
            'last_name' => (string) get_user_meta(
                $user->ID,
                'last_name',
                true
            ),
        );
    }

    /**
     * Authenticate requests using Bearer tokens.
     *
     * Also enforces inactivity timeout and refreshes last_used_at.
     */
    public function authenticate_request(WP_REST_Request $request) {

        $authorization = $request->get_header('authorization');

        if (
            !$authorization &&
            isset($_SERVER['HTTP_AUTHORIZATION'])
        ) {

            $authorization = sanitize_text_field(
                wp_unslash($_SERVER['HTTP_AUTHORIZATION'])
            );
        }

        if (
            !$authorization ||
            !preg_match(
                '/^Bearer\s+([a-f0-9]{64})$/i',
                trim($authorization),
                $matches
            )
        ) {

            return new WP_Error(
                'missing_or_invalid_token',
                'A valid Bearer token is required.',
                array('status' => 401)
            );
        }

        $token_hash = hash('sha256', $matches[1]);

        global $wpdb;

        $table = $this->token_table();

        $now = time();

        // Retrieve token information.
        $token_row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT user_id, last_used_at
                 FROM {$table}
                 WHERE token_hash = %s
                 AND expires_at > %s
                 LIMIT 1",
                $token_hash,
                gmdate('Y-m-d H:i:s', $now)
            )
        );

        if (!$token_row) {

            return new WP_Error(
                'invalid_or_expired_token',
                'Your session is invalid or has expired. Please sign in again.',
                array('status' => 401)
            );
        }

        // Calculate last activity.
        $last_used = $token_row->last_used_at
            ? strtotime($token_row->last_used_at . ' UTC')
            : false;

        // Revoke inactive token.
        if (
            !$last_used ||
            ($now - $last_used) >= self::INACTIVITY_TIMEOUT
        ) {

            $wpdb->delete(
                $table,
                array('token_hash' => $token_hash),
                array('%s')
            );

            return new WP_Error(
                'session_inactive',
                'Your session expired due to inactivity. Please sign in again.',
                array('status' => 401)
            );
        }

        // Retrieve WordPress user.
        $user = get_user_by(
            'id',
            (int) $token_row->user_id
        );

        if (!$user) {

            $wpdb->delete(
                $table,
                array('token_hash' => $token_hash),
                array('%s')
            );

            return new WP_Error(
                'user_not_found',
                'The account associated with this session no longer exists.',
                array('status' => 401)
            );
        }

        // Set authenticated WordPress user.
        wp_set_current_user($user->ID);

        // Refresh last activity.
        $wpdb->update(
            $table,
            array(
                'last_used_at' => gmdate(
                    'Y-m-d H:i:s',
                    $now
                ),
            ),
            array(
                'token_hash' => $token_hash,
            ),
            array('%s'),
            array('%s')
        );

        return true;
    }

    /**
     * Current authenticated user endpoint.
     */
    public function get_me(WP_REST_Request $request) {

        $user = wp_get_current_user();

        if (!$user || !$user->exists()) {

            return $this->response(array(
                'success' => false,
                'message' => 'Authenticated user could not be loaded.',
            ), 401);
        }

        return $this->response(array(
            'success' => true,
            'user' => $this->public_user_data($user),
        ));
    }

    /**
     * Heartbeat endpoint.
     *
     * The permission callback authenticates the token
     * and updates its last_used_at timestamp.
     */
    public function heartbeat(WP_REST_Request $request) {

        return $this->response(array(
            'success' => true,
            'message' => 'Session is active.',
            'server_time' => gmdate('c'),
        ));
    }

    /**
     * Logout endpoint.
     */
    public function logout(WP_REST_Request $request) {

        $authorization = $request->get_header('authorization');

        if (
            !$authorization &&
            isset($_SERVER['HTTP_AUTHORIZATION'])
        ) {

            $authorization = sanitize_text_field(
                wp_unslash($_SERVER['HTTP_AUTHORIZATION'])
            );
        }

        preg_match(
            '/^Bearer\s+([a-f0-9]{64})$/i',
            trim((string) $authorization),
            $matches
        );

        if (!empty($matches[1])) {

            global $wpdb;

            $wpdb->delete(
                $this->token_table(),
                array(
                    'token_hash' => hash(
                        'sha256',
                        $matches[1]
                    ),
                ),
                array('%s')
            );
        }

        return $this->response(array(
            'success' => true,
            'message' => 'You have been signed out.',
        ));
    }
}

/**
 * Plugin activation.
 */
register_activation_hook(
    __FILE__,
    array('PsalmoteeData_Mobile_API', 'activate')
);

/**
 * Initialize plugin.
 */
PsalmoteeData_Mobile_API::instance();