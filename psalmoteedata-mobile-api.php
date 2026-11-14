<?php
/**
 * Plugin Name: PsalmoteeData Mobile API
 * Description: Secure mobile authentication endpoints for the PsalmoteeData app.
 * Version: 0.3.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Psalmotee-Tech
 * Text Domain: psalmoteedata-mobile-api
 */

if (!defined('ABSPATH')) {
    exit;
}

final class PsalmoteeData_Mobile_API {

    const VERSION = '0.3.0';
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

    /**
     * Prevent direct instantiation.
     */
    private function __construct() {

        add_action(
            'rest_api_init',
            array($this, 'register_routes')
        );

        // Revoke sessions when a password is changed.
        add_action(
            'wp_set_password',
            array($this, 'handle_password_changed'),
            10,
            3
        );

        // Handle password reset flows.
        add_action(
            'after_password_reset',
            array($this, 'handle_password_reset'),
            10,
            2
        );

        // Detect password changes through profile updates.
        add_action(
            'profile_update',
            array($this, 'handle_profile_update'),
            10,
            2
        );
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
     * Revoke all mobile sessions belonging to a user.
     */
    private function revoke_user_sessions($user_id) {

        global $wpdb;

        $user_id = absint($user_id);

        if (!$user_id) {
            return false;
        }

        $deleted = $wpdb->delete(
            $this->token_table(),
            array(
                'user_id' => $user_id,
            ),
            array('%d')
        );

        return $deleted !== false;
    }

    /**
     * Create a new mobile session and invalidate previous sessions.
     *
     * A database lock prevents concurrent logins for the same user
     * from creating multiple active sessions.
     */
    private function create_single_user_session(
        $user_id,
        $plain_token,
        $created_at,
        $expires_at
    ) {

        global $wpdb;

        $user_id = absint($user_id);

        if (!$user_id) {
            return false;
        }

        $token_hash = hash('sha256', $plain_token);

        // Generate a consistent lock name for this user.
        $lock_name = 'ptd_mobile_' . substr(
            hash('sha256', (string) $user_id),
            0,
            32
        );

        // Acquire a database lock for this user's login.
        $lock_acquired = $wpdb->get_var(
            $wpdb->prepare(
                'SELECT GET_LOCK(%s, 10)',
                $lock_name
            )
        );

        if ((string) $lock_acquired !== '1') {
            return false;
        }

        try {

            // Insert the new session first.
            $inserted = $wpdb->insert(
                $this->token_table(),
                array(
                    'token_hash' => $token_hash,
                    'user_id' => $user_id,
                    'created_at' => $created_at,
                    'expires_at' => $expires_at,
                    'last_used_at' => $created_at,
                ),
                array('%s', '%d', '%s', '%s', '%s')
            );

            if (!$inserted) {
                return false;
            }

            // Remove every other mobile session belonging to this user.
            $deleted = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$this->token_table()}
                     WHERE user_id = %d
                     AND token_hash <> %s",
                    $user_id,
                    $token_hash
                )
            );

            // If previous sessions cannot be removed, revoke the new token.
            if ($deleted === false) {

                $wpdb->delete(
                    $this->token_table(),
                    array(
                        'token_hash' => $token_hash,
                    ),
                    array('%s')
                );

                return false;
            }

            return true;

        } finally {

            // Always release the database lock.
            $wpdb->get_var(
                $wpdb->prepare(
                    'SELECT RELEASE_LOCK(%s)',
                    $lock_name
                )
            );
        }
    }

    /**
     * Handle WordPress password changes.
     */
    public function handle_password_changed(
        $password,
        $user_id,
        $old_user_data = null
    ) {

        $this->revoke_user_sessions($user_id);
    }

    /**
     * Handle WordPress password resets.
     */
    public function handle_password_reset($user, $new_password) {

        if ($user instanceof WP_User) {

            $this->revoke_user_sessions($user->ID);
        }
    }

    /**
     * Detect password changes made through profile updates.
     */
    public function handle_profile_update($user_id, $old_user_data) {

        if (
            !($old_user_data instanceof WP_User) ||
            empty($old_user_data->user_pass)
        ) {
            return;
        }

        $current_user = get_userdata($user_id);

        if (!$current_user) {
            return;
        }

        // Compare old and new password hashes.
        if ($old_user_data->user_pass !== $current_user->user_pass) {

            $this->revoke_user_sessions($user_id);
        }
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
     *
     * Checks:
     * 1. VTU Press account synchronization.
     * 2. Account suspension status.
     * 3. Email verification when enabled.
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

        if (!$vt_user || !is_array($vt_user)) {

            return new WP_Error(
                'account_not_synced',
                'This account is not synchronized with VTU Press. Please contact support.',
                array('status' => 403)
            );
        }

        // Ensure the account status is available.
        if (!array_key_exists('access_status', $vt_user)) {

            return new WP_Error(
                'account_status_unavailable',
                'Unable to verify your account status. Please try again later.',
                array('status' => 503)
            );
        }

        // Reject suspended accounts.
        if ($vt_user['access_status'] === 'blocked') {

            return new WP_Error(
                'account_suspended',
                'Your account has been suspended. Please contact support.',
                array('status' => 403)
            );
        }

        // Load VTU Press settings.
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

        // Check email verification if enabled.
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

        // Find WordPress user.
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

        // Verify password.
        $authenticated_user = wp_authenticate(
            $wp_user->user_login,
            $password
        );

        // Reject invalid credentials.
        if (is_wp_error($authenticated_user)) {

            return $this->response(array(
                'success' => false,
                'message' => 'Invalid login details.',
            ), 401);
        }

        // Validate VTU Press account after password verification.
        $account_check = $this->validate_vtupress_account(
            $authenticated_user
        );

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

        // Create a new session and invalidate previous sessions.
        $inserted = $this->create_single_user_session(
            $authenticated_user->ID,
            $plain_token,
            $created_at,
            $expires_at
        );

        if (!$inserted) {

            return $this->response(array(
                'success' => false,
                'message' => 'Unable to create your session. Please try again.',
            ), 500);
        }

        // Clear login rate limit after successful login.
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
     * Enforces:
     * - Token validity.
     * - Token expiration.
     * - Inactivity timeout.
     * - WordPress user existence.
     * - VTU Press account status.
     *
     * Refreshes last_used_at after successful authentication.
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
                array(
                    'token_hash' => $token_hash,
                ),
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
                array(
                    'token_hash' => $token_hash,
                ),
                array('%s')
            );

            return new WP_Error(
                'user_not_found',
                'The account associated with this session no longer exists.',
                array('status' => 401)
            );
        }

        // Revalidate VTU Press account on every authenticated request.
        $account_check = $this->validate_vtupress_account($user);

        if (is_wp_error($account_check)) {

            // Immediately revoke all sessions if account is suspended.
            if (
                $account_check->get_error_code() === 'account_suspended'
            ) {

                $this->revoke_user_sessions($user->ID);
            }

            return $account_check;
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