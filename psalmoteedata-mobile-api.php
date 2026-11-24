<?php
/**
 * Plugin Name: PsalmoteeData Mobile API
 * Description: Secure mobile authentication endpoints for the PsalmoteeData app.
 * Version: 0.8.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Psalmotee-Tech
 * Text Domain: psalmoteedata-mobile-api
 */

if (!defined('ABSPATH')) {
    exit;
}

final class PsalmoteeData_Mobile_API {

    const VERSION = '0.8.0';
    const REST_NAMESPACE = 'psalmoteedata-mobile/v1';

    // Maximum lifetime of an authentication token.
    const TOKEN_LIFETIME = 30 * DAY_IN_SECONDS;

    // Session expires after five minutes without authenticated activity.
    const INACTIVITY_TIMEOUT = 5 * MINUTE_IN_SECONDS;

    // Login protection.
    const LOGIN_LIMIT = 10;
    const LOGIN_WINDOW = 15 * MINUTE_IN_SECONDS;

    // Account activation protection.
    const ACTIVATION_LIMIT = 5;
    const ACTIVATION_WINDOW = 15 * MINUTE_IN_SECONDS;

    // Resend activation email protection.
    const RESEND_ACTIVATION_LIMIT = 5;
    const RESEND_ACTIVATION_WINDOW = 15 * MINUTE_IN_SECONDS;

    // Registration protection.
    const REGISTRATION_LIMIT = 5;
    const REGISTRATION_WINDOW = 15 * MINUTE_IN_SECONDS;

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

         // Account registration.
        register_rest_route(self::REST_NAMESPACE, '/register', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'register_account'),
            'permission_callback' => '__return_true',
        ));

        // Enabled registration countries.
        register_rest_route(self::REST_NAMESPACE, '/countries', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_countries'),
            'permission_callback' => '__return_true',
        ));

        // Registration configuration.
        register_rest_route(self::REST_NAMESPACE, '/registration-config', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_registration_config'),
            'permission_callback' => '__return_true',
        ));


        // Account activation.
        register_rest_route(self::REST_NAMESPACE, '/activate', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'activate_account'),
            'permission_callback' => '__return_true',
        ));

        // Resend account activation email.
        register_rest_route(self::REST_NAMESPACE, '/resend-activation', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'resend_activation_email'),
            'permission_callback' => '__return_true',
        ));

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

        // Current authenticated user's wallet balance.
        register_rest_route(self::REST_NAMESPACE, '/wallet', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_wallet_balance'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));

        // Current authenticated user's wallet transaction history.
        register_rest_route(self::REST_NAMESPACE, '/wallet/history', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_wallet_history'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));
        
        // Current authenticated user's service transaction history.
        register_rest_route(self::REST_NAMESPACE, '/transactions', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_service_transaction_history'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));

        // Current authenticated user's virtual accounts.
        register_rest_route(self::REST_NAMESPACE, '/virtual-accounts', array(
            'methods' => WP_REST_Server::READABLE,
            'callback' => array($this, 'get_virtual_accounts'),
            'permission_callback' => array($this, 'authenticate_request'),
        ));

        // Generate virtual accounts for the authenticated user.
        register_rest_route(self::REST_NAMESPACE, '/virtual-accounts/generate', array(
            'methods' => WP_REST_Server::CREATABLE,
            'callback' => array($this, 'generate_virtual_accounts'),
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
     * Get countries enabled for account registration.
     */
    public function get_countries(WP_REST_Request $request)
    {
        // Confirm that the VTU Press country manager is available.
        if (
            !class_exists('Vtupress_Country_Manager') ||
            !method_exists('Vtupress_Country_Manager', 'enabled')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Country registration services are unavailable.',
            ), 503);
        }

        // Retrieve the same enabled countries used by the website.
        $enabled_countries = Vtupress_Country_Manager::enabled();

        if (!is_array($enabled_countries)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve available countries.',
            ), 503);
        }

        $countries = array();

        foreach ($enabled_countries as $key) {
            $key = (string) $key;

            $countries[] = array(
                'value' => strtolower($key),
                'label' => ucfirst($key),
            );
        }

        return $this->response(array(
            'success' => true,
            'countries' => $countries,
        ));
    }

    /**
     * Get public registration configuration.
     */
    public function get_registration_config(WP_REST_Request $request)
    {
        $manual_gateway = class_exists('Vtupress_Gateway_Container')
            ? Vtupress_Gateway_Container::get('manual')
            : null;

        $manual_settings = $manual_gateway
            ? $manual_gateway->get_settings()
            : array();

        $request_bvn_nin = (
            $manual_settings['request_bvn_nin'] ?? 'no'
        ) === 'yes';

        $request_bvn_nin_required = (
            $manual_settings['request_bvn_nin_required'] ?? 'no'
        ) === 'yes';

        return $this->response(array(
            'success' => true,
            'registration' => array(
                'request_bvn_nin' => $request_bvn_nin,
                'request_bvn_nin_required' => $request_bvn_nin_required,
            ),
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
     * Generate registration rate-limit key.
     */
    private function registration_rate_key()
    {
        return 'ptd_mobile_register_' . hash(
            'sha256',
            $this->client_ip()
        );
    }

    /**
     * Check registration rate limit.
     */
    private function registration_rate_limited()
    {
        $key = $this->registration_rate_key();

        $attempts = (int) get_transient($key);

        if ($attempts >= self::REGISTRATION_LIMIT) {
            return true;
        }

        set_transient(
            $key,
            $attempts + 1,
            self::REGISTRATION_WINDOW
        );

        error_log(
            'Registration rate limit: ' .
            wp_json_encode(array(
                'attempts_before' => $attempts,
                'attempts_after' => $attempts + 1,
                'ip' => $this->client_ip(),
            ))
        );

        return false;
    }

    /**
     * Clear registration rate limit.
     */
    private function clear_registration_rate_limit()
    {
        delete_transient(
            $this->registration_rate_key()
        );
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
     * Generate account activation rate-limit key.
     */
    private function activation_rate_key($rate_identity)
    {
        return 'ptd_mobile_activate_' . hash(
            'sha256',
            $this->client_ip() . '|' . strtolower($rate_identity)
        );
    }

    /**
     * Check account activation rate limit.
     */
    private function activation_rate_limited($rate_identity)
    {
        $key = $this->activation_rate_key($rate_identity);
        $attempts = (int) get_transient($key);

        if ($attempts >= self::ACTIVATION_LIMIT) {
            return true;
        }

        set_transient(
            $key,
            $attempts + 1,
            self::ACTIVATION_WINDOW
        );

        return false;
    }

    /**
     * Clear activation rate limit after successful activation.
     */
    private function clear_activation_rate_limit($rate_identity)
    {
        delete_transient(
            $this->activation_rate_key($rate_identity)
        );
    }

    /**
     * Generate resend activation rate-limit key.
     */
    private function resend_activation_rate_key($rate_identity)
    {
        return 'ptd_mobile_resend_activation_' . hash(
            'sha256',
            $this->client_ip() . '|' . strtolower($rate_identity)
        );
    }

    /**
     * Check resend activation rate limit.
     */
    private function resend_activation_rate_limited($rate_identity)
    {
        $key = $this->resend_activation_rate_key($rate_identity);

        $attempts = (int) get_transient($key);

        if ($attempts >= self::RESEND_ACTIVATION_LIMIT) {
            return true;
        }

        set_transient(
            $key,
            $attempts + 1,
            self::RESEND_ACTIVATION_WINDOW
        );

        return false;
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
     * Validate a WordPress user's VTU Press account.
     *
     * Checks:
     * - WordPress user validity.
     * - VTU Press account existence.
     * - Account suspension status.
     * - Email verification requirements.
     */
    private function validate_vtupress_account($user)
    {
        if (
            !($user instanceof WP_User) ||
            !$user->exists()
        ) {
            return new WP_Error(
                'invalid_user',
                'The account could not be verified.',
                array('status' => 403)
            );
        }

        // Ensure VTU Press account services are available.
        if (
            !class_exists('Users') ||
            !method_exists('Users', 'getUser')
        ) {
            return new WP_Error(
                'account_service_unavailable',
                'Account services are temporarily unavailable.',
                array('status' => 503)
            );
        }

        $users_api = new Users();

        // Retrieve the VTU Press account using the WordPress user ID.
        $vt_user = $users_api->getUser(
            $user->ID,
            true,
            true
        );

        if (
            !$vt_user ||
            !is_array($vt_user) ||
            empty($vt_user['id'])
        ) {
            return new WP_Error(
                'vtu_account_not_found',
                'Your VTU Press account could not be found.',
                array('status' => 403)
            );
        }

        // Check whether the account has been blocked.
        $access_status = strtolower(
            trim((string) ($vt_user['access_status'] ?? ''))
        );

        if ($access_status === 'blocked') {
            return new WP_Error(
                'account_suspended',
                'Your account has been suspended. Please contact support.',
                array('status' => 403)
            );
        }

        // Retrieve VTU Press email verification settings.
        global $wpdb;

        $settings_table = $wpdb->prefix . 'vtupress_general_settings';

        $settings = $wpdb->get_row(
            "SELECT * FROM {$settings_table} ORDER BY id ASC LIMIT 1",
            ARRAY_A
        );

        if (empty($settings)) {
            return new WP_Error(
                'account_settings_unavailable',
                'Unable to verify your account settings. Please try again.',
                array('status' => 503)
            );
        }

        // Require activation only when email verification is enabled.
        $email_verification_enabled = (
            ($settings['enable_email_verification'] ?? 'no') === 'yes'
        );

        if ($email_verification_enabled) {

            $email_verified = strtolower(
                trim((string) ($vt_user['email_verified'] ?? ''))
            );

            if (!in_array($email_verified, array('yes', 'verified'), true)) {
                return new WP_Error(
                    'account_not_activated',
                    'Please activate your account before signing in.',
                    array('status' => 403)
                );
            }
        }

        return true;
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
     * Get the authenticated user's VTU Press wallet balance.
     *
     * The WordPress user ID is used to retrieve the linked
     * VTU Press account. The VTU Press internal ID is then
     * used to retrieve the wallet balance.
     */
    public function get_wallet_balance(WP_REST_Request $request)
    {
        $wp_user_id = get_current_user_id();

        if (!$wp_user_id) {
            return $this->response(array(
                'success' => false,
                'message' => 'Authenticated user could not be identified.',
            ), 401);
        }

        // Confirm that the VTU Press Users class is available.
        if (
            !class_exists('Users') ||
            !method_exists('Users', 'getUser') ||
            !method_exists('Users', 'getBalance')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Wallet service is currently unavailable.',
            ), 503);
        }

        $users_api = new Users();

        // Retrieve the VTU Press account using the WordPress user ID.
        $vt_user = $users_api->getUser(
            $wp_user_id,
            true,
            true
        );

        if (
            !$vt_user ||
            !is_array($vt_user) ||
            empty($vt_user['id'])
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your wallet account could not be found.',
            ), 404);
        }

        // Use the VTU Press internal user ID to retrieve the balance.
        $balance = $users_api->getBalance(
            (int) $vt_user['id']
        );

        return $this->response(array(
            'success' => true,
            'wallet' => array(
                'balance' => round((float) $balance, 2),
            ),
        ));
    }

    /**
     * Get the authenticated user's wallet transaction history.
     *
     * Uses the WordPress user ID to retrieve the linked VTU Press
     * account, then queries wallet records using the VTU Press ID.
     *
     * Supports pagination through page and per_page parameters.
     */
    public function get_wallet_history(WP_REST_Request $request)
    {
        global $wpdb;

        $wp_user_id = get_current_user_id();

        if (!$wp_user_id) {
            return $this->response(array(
                'success' => false,
                'message' => 'Authenticated user could not be identified.',
            ), 401);
        }

        // Confirm that the VTU Press Users class is available.
        if (
            !class_exists('Users') ||
            !method_exists('Users', 'getUser')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Wallet service is currently unavailable.',
            ), 503);
        }

        // Retrieve the VTU Press account using the WordPress user ID.
        $users_api = new Users();

        $vt_user = $users_api->getUser(
            $wp_user_id,
            true,
            true
        );

        if (
            !$vt_user ||
            !is_array($vt_user) ||
            empty($vt_user['id'])
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your wallet account could not be found.',
            ), 404);
        }

        // Use the VTU Press internal user ID.
        $vtu_user_id = (int) $vt_user['id'];

        // Pagination parameters.
        $page = max(1, absint($request->get_param('page')));

        $per_page = absint($request->get_param('per_page'));

        if ($per_page < 1) {
            $per_page = 20;
        }

        // Prevent excessively large requests.
        $per_page = min($per_page, 100);

        $offset = ($page - 1) * $per_page;

        // VTU Press wallet table.
        $wallet_table = $wpdb->prefix . 'vtupress_wallet';

        // Count the user's wallet transactions.
        $total = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*)
                FROM {$wallet_table}
                WHERE user_id = %d",
                $vtu_user_id
            )
        );

        if ($total === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve wallet transaction history.',
            ), 500);
        }

        $total = (int) $total;

        // Retrieve the user's transactions, newest first.
        $transactions = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT
                    id,
                    type,
                    fund_amount,
                    before_amount,
                    now_amount,
                    name,
                    status,
                    the_time
                FROM {$wallet_table}
                WHERE user_id = %d
                ORDER BY id DESC
                LIMIT %d OFFSET %d",
                $vtu_user_id,
                $per_page,
                $offset
            ),
            ARRAY_A
        );

        if ($transactions === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve wallet transactions.',
            ), 500);
        }

        // Format transaction records for the mobile application.
        $formatted_transactions = array();

        foreach ($transactions as $transaction) {
            $formatted_transactions[] = array(
                'id' => (int) $transaction['id'],
                'type' => (string) $transaction['type'],
                'name' => (string) $transaction['name'],
                'amount' => round((float) $transaction['fund_amount'], 2),
                'balance_before' => round((float) $transaction['before_amount'], 2),
                'balance_after' => round((float) $transaction['now_amount'], 2),
                'status' => (string) $transaction['status'],
                'date' => (string) $transaction['the_time'],
            );
        }

        return $this->response(array(
            'success' => true,
            'transactions' => $formatted_transactions,
            'pagination' => array(
                'current_page' => $page,
                'per_page' => $per_page,
                'total' => $total,
                'total_pages' => (int) ceil($total / $per_page),
            ),
        ));
    }

    /**
     * Get the authenticated user's service transaction history.
     *
     * Retrieves the authenticated WordPress user's linked VTU Press
     * account and queries service transactions using the VTU Press ID.
     *
     * Supports pagination through page and per_page parameters.
     */
    public function get_service_transaction_history(WP_REST_Request $request)
    {
        global $wpdb;

        $wp_user_id = get_current_user_id();

        if (!$wp_user_id) {
            return $this->response(array(
                'success' => false,
                'message' => 'Authenticated user could not be identified.',
            ), 401);
        }

        // Confirm that the VTU Press Users class is available.
        if (
            !class_exists('Users') ||
            !method_exists('Users', 'getUser')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Transaction service is currently unavailable.',
            ), 503);
        }

        // Retrieve the VTU Press account using the WordPress user ID.
        $users_api = new Users();

        $vt_user = $users_api->getUser(
            $wp_user_id,
            true,
            true
        );

        if (
            !$vt_user ||
            !is_array($vt_user) ||
            empty($vt_user['id'])
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your transaction account could not be found.',
            ), 404);
        }

        // Use the VTU Press internal user ID.
        $vtu_user_id = (int) $vt_user['id'];

        // Pagination parameters.
        $page = max(1, absint($request->get_param('page')));

        $per_page = absint($request->get_param('per_page'));

        if ($per_page < 1) {
            $per_page = 20;
        }

        // Prevent excessively large requests.
        $per_page = min($per_page, 100);

        $offset = ($page - 1) * $per_page;

        // VTU Press service transactions table.
        $transactions_table = $wpdb->prefix . 'vtupress_transactions';

        // Count the user's service transactions.
        $total = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*)
                FROM {$transactions_table}
                WHERE user_id = %d",
                $vtu_user_id
            )
        );

        if ($total === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve service transaction history.',
            ), 500);
        }

        $total = (int) $total;

        // Retrieve the user's transactions, newest first.
        // The details column contains additional VTU Press transaction data.
        $transactions = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT
                    id,
                    service,
                    recipient,
                    amount,
                    status,
                    via,
                    reference,
                    balance_before,
                    balance_now,
                    description,
                    set_country,
                    created_at,
                    details
                FROM {$transactions_table}
                WHERE user_id = %d
                ORDER BY id DESC
                LIMIT %d OFFSET %d",
                $vtu_user_id,
                $per_page,
                $offset
            ),
            ARRAY_A
        );

        if ($transactions === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve service transactions.',
            ), 500);
        }

        // Safely retrieve a scalar value from transaction details.
        $get_detail_value = function ($details, $keys, $default = '') {

            foreach ($keys as $key) {

                if (
                    isset($details[$key]) &&
                    is_scalar($details[$key]) &&
                    trim((string) $details[$key]) !== ''
                ) {
                    return trim((string) $details[$key]);
                }
            }

            return $default;
        };

        // Format transaction records for the mobile application.
        $formatted_transactions = array();

        foreach ($transactions as $transaction) {

            // Decode the VTU Press details JSON.
            $details = array();

            if (!empty($transaction['details'])) {
                $decoded_details = json_decode(
                    $transaction['details'],
                    true
                );

                if (is_array($decoded_details)) {
                    $details = $decoded_details;
                }
            }

            $service = strtolower(
                (string) $transaction['service']
            );

            // Resolve the actual recipient.
            // VTU Press may store "system" in the database recipient column.
            $recipient = $get_detail_value(
                $details,
                array('recipient', 'mobile_number', 'phone_number')
            );

            if (
                $recipient === '' &&
                strtolower((string) $transaction['recipient']) !== 'system'
            ) {
                $recipient = (string) $transaction['recipient'];
            }

            // Resolve the purchased plan.
            $plan = '';

            if ($service === 'airtime') {
                $plan = $get_detail_value(
                    $details,
                    array('plan_amount', 'amount')
                );
            } elseif ($service === 'data') {
                $plan = $get_detail_value(
                    $details,
                    array('plan_text', 'dataplan', 'plan')
                );
            } else {
                $plan = $get_detail_value(
                    $details,
                    array('plan_text', 'dataplan', 'plan', 'plan_amount')
                );
            }

            // Resolve provider/network.
            $provider = $get_detail_value(
                $details,
                array('provider', 'plan_network', 'network')
            );

            // Resolve transaction type.
            // Airtime uses airtime_type, while data uses type.
            if ($service === 'airtime') {
                $type = $get_detail_value(
                    $details,
                    array('airtime_type', 'type')
                );
            } else {
                $type = $get_detail_value(
                    $details,
                    array('type', 'plan_type')
                );
            }

            // Resolve reference, status, and payment channel.
            $reference = $get_detail_value(
                $details,
                array('ref', 'transid', 'request-id'),
                (string) $transaction['reference']
            );

            $status = $get_detail_value(
                $details,
                array('status', 'Status'),
                (string) ($transaction['status'] ?? '')
            );

            $via = $get_detail_value(
                $details,
                array('via'),
                (string) ($transaction['via'] ?? '')
            );

            // Balance columns are TEXT in the VTU Press database.
            $balance_before = is_numeric($transaction['balance_before'])
                ? round((float) $transaction['balance_before'], 2)
                : null;

            $balance_after = is_numeric($transaction['balance_now'])
                ? round((float) $transaction['balance_now'], 2)
                : null;

            // Use the transaction table amount as the recorded transaction amount.
            // Do not substitute details.amount or paid_amount because VTU Press
            // records can contain different values in these fields.
            $amount = round((float) $transaction['amount'], 2);

            // Use the transaction table date, with create_date as a fallback.
            $date = $transaction['created_at'] !== null
                ? (string) $transaction['created_at']
                : $get_detail_value(
                    $details,
                    array('create_date'),
                    null
                );

            $formatted_transactions[] = array(
                'id' => (int) $transaction['id'],
                'service' => (string) $transaction['service'],
                'recipient' => $recipient,
                'amount' => $amount,
                'status' => $status,
                'via' => $via,
                'reference' => $reference,

                // Additional receipt information.
                'plan' => $plan,
                'provider' => $provider,
                'type' => $type,

                // Existing history fields retained for compatibility.
                'balance_before' => $balance_before,
                'balance_after' => $balance_after,
                'description' => $transaction['description'] !== null
                    ? (string) $transaction['description']
                    : null,
                'country' => (string) $transaction['set_country'],
                'date' => $date,
            );
        }

        return $this->response(array(
            'success' => true,
            'transactions' => $formatted_transactions,
            'pagination' => array(
                'current_page' => $page,
                'per_page' => $per_page,
                'total' => $total,
                'total_pages' => (int) ceil($total / $per_page),
            ),
        ));
    }

    /**
     * Get the authenticated user's saved virtual accounts.
     *
     * WordPress user ID is resolved to the VTU Press internal
     * user ID before querying vtupress_userAccounts.
     */
    public function get_virtual_accounts(WP_REST_Request $request)
    {
        global $wpdb;

        $wp_user_id = get_current_user_id();

        if (!$wp_user_id) {
            return $this->response(array(
                'success' => false,
                'message' => 'Authenticated user could not be identified.',
            ), 401);
        }

        // Confirm VTU Press user service is available.
        if (
            !class_exists('Users') ||
            !method_exists('Users', 'getUser')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Virtual account service is currently unavailable.',
            ), 503);
        }

        // Resolve WordPress user ID to VTU Press internal user ID.
        $users_api = new Users();

        $vt_user = $users_api->getUser(
            $wp_user_id,
            true,
            true
        );

        if (
            !$vt_user ||
            !is_array($vt_user) ||
            empty($vt_user['id'])
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your VTU Press account could not be found.',
            ), 404);
        }

        $vt_user_id = (int) $vt_user['id'];

        $accounts_table = $wpdb->prefix . 'vtupress_userAccounts';

        // Retrieve only the authenticated user's saved accounts.
        $accounts = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT
                    id,
                    bankName,
                    accountName,
                    accountNumber,
                    accountRef,
                    gateway,
                    created_at,
                    updated_at
                FROM {$accounts_table}
                WHERE userId = %d
                ORDER BY id DESC",
                $vt_user_id
            ),
            ARRAY_A
        );

        if ($accounts === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve virtual accounts.',
            ), 500);
        }

        $formatted_accounts = array();
        $seen_accounts = array();

        foreach ($accounts as $account) {

            $account_number = trim((string) ($account['accountNumber'] ?? ''));
            $gateway = strtolower(trim((string) ($account['gateway'] ?? '')));

            // Ignore incomplete account records.
            if ($account_number === '' || $gateway === '') {
                continue;
            }

            // Ignore obvious placeholder account numbers.
            if ($account_number === '1') {
                continue;
            }

            // Prevent duplicate accounts for the same gateway.
            $unique_key = $gateway . ':' . $account_number;

            if (isset($seen_accounts[$unique_key])) {
                continue;
            }

            $seen_accounts[$unique_key] = true;

            $formatted_accounts[] = array(
                'id' => (int) $account['id'],
                'bank_name' => (string) $account['bankName'],
                'account_name' => (string) $account['accountName'],
                'account_number' => $account_number,
                'account_reference' => (string) ($account['accountRef'] ?? ''),
                'gateway' => $gateway,
                'created_at' => $account['created_at'] ?? null,
                'updated_at' => $account['updated_at'] ?? null,
            );
        }

        return $this->response(array(
            'success' => true,
            'accounts' => $formatted_accounts,
            'total' => count($formatted_accounts),
        ));
    }

    /**
     * Generate virtual accounts across all eligible VTU Press gateways.
     *
     * The authenticated WordPress user ID is passed to each gateway.
     * Existing valid accounts are not regenerated.
     */
    public function generate_virtual_accounts(WP_REST_Request $request)
    {
        global $wpdb;

        $wp_user_id = get_current_user_id();

        if (!$wp_user_id) {
            return $this->response(array(
                'success' => false,
                'message' => 'Authenticated user could not be identified.',
            ), 401);
        }

        // Check required VTU Press services.
        if (
            !class_exists('Users') ||
            !class_exists('Vtupress_Gateway_Container') ||
            !class_exists('Vtupress_Option')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Virtual account services are currently unavailable.',
            ), 503);
        }

        // Resolve WordPress user to VTU Press user.
        $users_api = new Users();

        $vp_user = $users_api->getUser(
            $wp_user_id,
            false,
            true
        );

        if (empty($vp_user) || empty($vp_user->id)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your VTU Press account could not be found.',
            ), 404);
        }

        $vp_user_id = (int) $vp_user->id;

        // Check global banking availability.
        $banking_enabled = Vtupress_Option::get('banking', 'yes') === 'yes';

        if (!$banking_enabled) {
            return $this->response(array(
                'success' => false,
                'message' => 'Virtual banking is currently disabled.',
            ), 403);
        }

        // Check whether virtual payments are enabled.
        $manual_gateway = Vtupress_Gateway_Container::get('manual');

        if (!$manual_gateway) {
            return $this->response(array(
                'success' => false,
                'message' => 'Virtual account configuration is unavailable.',
            ), 503);
        }

        $manual_settings = $manual_gateway->get_settings();

        if (($manual_settings['virtual_payment'] ?? 'no') !== 'yes') {
            return $this->response(array(
                'success' => false,
                'message' => 'Virtual account generation is currently disabled.',
            ), 403);
        }

        // Retrieve all gateways available in the current VTU Press context.
        $gateways = Vtupress_Gateway_Container::all();

        if (empty($gateways)) {
            return $this->response(array(
                'success' => false,
                'message' => 'No virtual account gateways are currently available.',
            ), 503);
        }

        $accounts_table = $wpdb->prefix . 'vtupress_userAccounts';

        // Retrieve existing accounts for this VTU Press user.
        $existing_accounts = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT gateway, accountNumber
                FROM {$accounts_table}
                WHERE userId = %d",
                $vp_user_id
            ),
            ARRAY_A
        );

        if ($existing_accounts === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to check your existing virtual accounts.',
            ), 500);
        }

        // Identify gateways that already have valid accounts.
        $existing_gateways = array();

        foreach ($existing_accounts as $account) {

            $gateway_id = strtolower(trim((string) ($account['gateway'] ?? '')));
            $account_number = trim((string) ($account['accountNumber'] ?? ''));

            if (
                $gateway_id !== '' &&
                $account_number !== '' &&
                $account_number !== '1'
            ) {
                $existing_gateways[$gateway_id] = true;
            }
        }

        $results = array();

        foreach ($gateways as $gateway_id => $gateway) {

            $gateway_id = strtolower((string) $gateway_id);

            // Ignore gateways without virtual account support.
            if (empty($gateway->virtual_account)) {
                continue;
            }

            $settings = $gateway->get_settings();

            // Ignore inactive gateways.
            if (($settings['status'] ?? 'inactive') !== 'active') {
                continue;
            }

            // Check configured banks.
            $saved_raw = Vtupress_Option::get(
                $gateway->get_option_key(),
                array()
            );

            $saved_banks = isset($saved_raw['banks'])
                ? trim((string) $saved_raw['banks'])
                : '';

            // Ignore gateways without configured banks.
            if ($saved_banks === '') {
                continue;
            }

            // Do not regenerate an account that already exists.
            if (isset($existing_gateways[$gateway_id])) {

                $results[] = array(
                    'gateway' => $gateway_id,
                    'status' => 'already_exists',
                    'message' => 'A valid account already exists for this gateway.',
                );

                continue;
            }

            // Phone number is required by the existing VTU Press account renderer.
            if (empty($vp_user->phone)) {

                $results[] = array(
                    'gateway' => $gateway_id,
                    'status' => 'profile_required',
                    'message' => 'Please add your phone number to your profile.',
                );

                continue;
            }

            // Check gateway-specific BVN requirement.
            $requires_bvn = strtolower(
                (string) ($settings['requires_bvn'] ?? 'no')
            ) === 'yes';

            if ($requires_bvn && empty($vp_user->bvn)) {

                $results[] = array(
                    'gateway' => $gateway_id,
                    'status' => 'profile_required',
                    'message' => 'Please add your BVN to your profile.',
                );

                continue;
            }

            // Check gateway-specific NIN requirement.
            $requires_nin = strtolower(
                (string) ($settings['requires_nin'] ?? 'no')
            ) === 'yes';

            if ($requires_nin && empty($vp_user->nin)) {

                $results[] = array(
                    'gateway' => $gateway_id,
                    'status' => 'profile_required',
                    'message' => 'Please add your NIN to your profile.',
                );

                continue;
            }

            // Confirm that the gateway implements account generation.
            if (!method_exists($gateway, 'create_virtual_account')) {
                continue;
            }

            try {

                // Gateway expects the WordPress user ID, not the VTU Press ID.
                $generation = $gateway->create_virtual_account($wp_user_id);

                if (
                    is_array($generation) &&
                    ($generation['status'] ?? '') === 'success'
                ) {

                    $results[] = array(
                        'gateway' => $gateway_id,
                        'status' => 'success',
                        'message' => 'Account generation request completed.',
                    );

                } else {

                    $results[] = array(
                        'gateway' => $gateway_id,
                        'status' => 'failed',
                        'message' => 'The gateway could not generate an account.',
                    );
                }

            } catch (Throwable $exception) {

                // Log technical details without exposing them to the mobile app.
                error_log(
                    'PsalmoteeData virtual account generation failed for ' .
                    $gateway_id . ': ' . $exception->getMessage()
                );

                $results[] = array(
                    'gateway' => $gateway_id,
                    'status' => 'failed',
                    'message' => 'An error occurred while generating this account.',
                );
            }
        }

        // Count gateway outcomes.
        $generated = 0;
        $failed = 0;
        $already_exists = 0;
        $profile_required = 0;

        foreach ($results as $result) {

            switch ($result['status']) {

                case 'success':
                    $generated++;
                    break;

                case 'failed':
                    $failed++;
                    break;

                case 'already_exists':
                    $already_exists++;
                    break;

                case 'profile_required':
                    $profile_required++;
                    break;
            }
        }

        // Retrieve the latest saved accounts after generation.
        $saved_accounts = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT
                    id,
                    bankName,
                    accountName,
                    accountNumber,
                    accountRef,
                    gateway,
                    created_at,
                    updated_at
                FROM {$accounts_table}
                WHERE userId = %d
                ORDER BY id DESC",
                $vp_user_id
            ),
            ARRAY_A
        );

        if ($saved_accounts === null) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to retrieve your virtual accounts after generation.',
            ), 500);
        }

        $formatted_accounts = array();
        $seen_accounts = array();

        foreach ($saved_accounts as $account) {

            $account_number = trim((string) ($account['accountNumber'] ?? ''));
            $account_gateway = strtolower(trim((string) ($account['gateway'] ?? '')));

            // Ignore incomplete account records and placeholders.
            if (
                $account_number === '' ||
                $account_number === '1' ||
                $account_gateway === ''
            ) {
                continue;
            }

            // Prevent duplicate accounts for the same gateway.
            $unique_key = $account_gateway . ':' . $account_number;

            if (isset($seen_accounts[$unique_key])) {
                continue;
            }

            $seen_accounts[$unique_key] = true;

            $formatted_accounts[] = array(
                'id' => (int) $account['id'],
                'bank_name' => (string) $account['bankName'],
                'account_name' => (string) $account['accountName'],
                'account_number' => $account_number,
                'account_reference' => (string) ($account['accountRef'] ?? ''),
                'gateway' => $account_gateway,
                'created_at' => $account['created_at'] ?? null,
                'updated_at' => $account['updated_at'] ?? null,
            );
        }

        return $this->response(array(
            'success' => true,
            'message' => 'Virtual account generation process completed.',
            'summary' => array(
                'generated' => $generated,
                'failed' => $failed,
                'already_exists' => $already_exists,
                'profile_required' => $profile_required,
                'total_accounts' => count($formatted_accounts),
            ),
            'results' => $results,
            'accounts' => $formatted_accounts,
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
     * Activate a VTU Press account.
     *
     * Accepts a username or email address and validates
     * the activation code before marking the account as verified.
     */
    public function activate_account(WP_REST_Request $request)
    {
        $identifier = trim(
            (string) $request->get_param('identifier')
        );

        $activation_code = trim(
            sanitize_text_field((string) $request->get_param('activation_code'))
        );

        // Normalize the identifier.
        if (is_email($identifier)) {
            $identifier = strtolower(sanitize_email($identifier));
        } else {
            $identifier = sanitize_user($identifier);
        }

        if ($identifier === '' || $activation_code === '') {
            return $this->response(array(
                'success' => false,
                'message' => 'Username/email and activation code are required.',
            ), 400);
        }

        // Activation codes generated by this API contain exactly five digits.
        if (!preg_match('/^[0-9]{5}$/', $activation_code)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please enter a valid five-digit activation code.',
            ), 400);
        }

        // Protect against repeated activation attempts.
        
        if ($this->activation_rate_limited($identifier)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Too many activation attempts. Please wait and try again.',
            ), 429);
        }

       // Resolve the identifier as either an email or username.
        $wp_user = is_email($identifier)
            ? get_user_by('email', $identifier)
            : get_user_by('login', $identifier);

        // Use the same rate-limit identity for both username and email.
        $rate_identity = $wp_user
            ? 'user:' . (int) $wp_user->ID
            : 'identifier:' . strtolower($identifier);

        // Protect against repeated activation attempts.
        if ($this->activation_rate_limited($rate_identity)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Too many activation attempts. Please wait and try again.',
            ), 429);
        }

        if (!$wp_user) {
            return $this->response(array(
                'success' => false,
                'message' => 'Invalid username/email or activation code.',
            ), 400);
        }
                

        // Ensure VTU Press services are available.
        if (!class_exists('Users')) {
            return $this->response(array(
                'success' => false,
                'message' => 'Account services are temporarily unavailable.',
            ), 503);
        }

        $users_api = new Users();

        // Retrieve the VTU Press account using the WordPress user ID.
        $vt_user = $users_api->getUser(
            $wp_user->ID,
            true,
            true
        );

        if (!$vt_user || !is_array($vt_user) || empty($vt_user['id'])) {
            return $this->response(array(
                'success' => false,
                'message' => 'Invalid username/email or activation code.',
            ), 400);
        }

        $email_verified = (string) ($vt_user['email_verified'] ?? '');

        // Check whether the account has already been activated.
        if (in_array($email_verified, array('yes', 'verified'), true)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your account has already been activated.',
                'code' => 'already_activated',
            ), 409);
        }

        // Support existing VTU Press activation-code formats.
        $stored_code = (string) ($vt_user['reset_code'] ?? '');

        $legacy_code = (
            $email_verified !== 'false' &&
            $email_verified !== 'verified'
        ) ? $email_verified : '';

        $code_matches = (
            ($stored_code !== '' && hash_equals($stored_code, $activation_code)) ||
            ($legacy_code !== '' && hash_equals($legacy_code, $activation_code))
        );

        if (!$code_matches) {
            return $this->response(array(
                'success' => false,
                'message' => 'Invalid username/email or activation code.',
            ), 400);
        }

        /*
        * IMPORTANT:
        * Users::update() expects the VTU Press record ID,
        * not the WordPress user ID.
        */
        $updated = $users_api->update(
            (int) $vt_user['id'],
            array(
                'email_verified' => 'yes',
                'reset_code' => '',
            )
        );

        if (!$updated) {
            return $this->response(array(
                'success' => false,
                'message' => 'Unable to activate your account. Please try again.',
            ), 500);
        }

        // Clear the activation rate limit after successful activation.
        $this->clear_activation_rate_limit($rate_identity);

        return $this->response(array(
            'success' => true,
            'message' => 'Your account has been activated successfully.',
            'user' => array(
                'username' => $wp_user->user_login,
            ),
        ));
    }

    /**
     * Resend account activation email.
     *
     * Accepts a username or email address.
     * Uses a generic response to prevent account enumeration.
     */
    public function resend_activation_email(WP_REST_Request $request)
    {
        $identifier = trim(
            (string) $request->get_param('identifier')
        );

        if (is_email($identifier)) {
            $identifier = strtolower(sanitize_email($identifier));
        } else {
            $identifier = sanitize_user($identifier);
        }

        if ($identifier === '') {
            return $this->response(array(
                'success' => false,
                'message' => 'Username or email is required.',
            ), 400);
        }

        $generic_response = array(
            'success' => true,
            'message' => 'If your account requires email verification, an activation code will be sent to your registered email address.',
        );

        // Resolve the identifier.
        $wp_user = is_email($identifier)
            ? get_user_by('email', $identifier)
            : get_user_by('login', $identifier);

        // Share the rate limit between username and email.
        $rate_identity = $wp_user
            ? 'user:' . (int) $wp_user->ID
            : 'identifier:' . strtolower($identifier);

        if ($this->resend_activation_rate_limited($rate_identity)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Too many requests. Please wait before requesting another activation email.',
            ), 429);
        }

        if (!$wp_user) {
            return $this->response($generic_response);
        }

        if (!class_exists('Users')) {
            error_log('PsalmoteeData Mobile API: VTU Press Users class unavailable during activation resend.');
            return $this->response($generic_response);
        }

        $users_api = new Users();

        $vt_user = $users_api->getUser(
            $wp_user->ID,
            true,
            true
        );

        if (
            !$vt_user ||
            !is_array($vt_user) ||
            empty($vt_user['id'])
        ) {
            return $this->response($generic_response);
        }

        $email_verified = (string) ($vt_user['email_verified'] ?? '');

        if (in_array($email_verified, array('yes', 'verified'), true)) {
            return $this->response($generic_response);
        }

        global $wpdb;

        $settings_table = $wpdb->prefix . 'vtupress_general_settings';

        $settings = $wpdb->get_row(
            "SELECT * FROM {$settings_table} ORDER BY id ASC LIMIT 1",
            ARRAY_A
        );

        if (empty($settings)) {
            error_log('PsalmoteeData Mobile API: Unable to load VTU Press settings during activation resend.');
            return $this->response($generic_response);
        }

        if (
            !isset($settings['enable_email_verification']) ||
            $settings['enable_email_verification'] !== 'yes'
        ) {
            return $this->response($generic_response);
        }

        $email = sanitize_email($wp_user->user_email);

        if (!is_email($email)) {
            return $this->response($generic_response);
        }

        if (!class_exists('Vtupress_Mail')) {
            error_log('PsalmoteeData Mobile API: VTU Press mail service unavailable during activation resend.');
            return $this->response($generic_response);
        }

        try {
            $code = (string) random_int(10000, 99999);
        } catch (Throwable $e) {
            error_log('PsalmoteeData Mobile API: Failed to generate activation code.');
            return $this->response($generic_response);
        }

        $previous_code = (string) ($vt_user['reset_code'] ?? '');

        // Update the VTU Press record using its own record ID.
        $updated = $users_api->update(
            (int) $vt_user['id'],
            array(
                'reset_code' => $code,
            )
        );

        if (!$updated) {
            error_log('PsalmoteeData Mobile API: Failed to save activation code.');
            return $this->response($generic_response);
        }

        $mailer = new Vtupress_Mail();

        $email_sent = $mailer->sendMail(
            $email,
            'Account Verification',
            'Your activation code is <strong>' .
                esc_html($code) .
                '</strong>'
        );

        if (!$email_sent) {
            // Restore the previous code if delivery fails.
            $restored = $users_api->update(
                (int) $vt_user['id'],
                array(
                    'reset_code' => $previous_code,
                )
            );

            error_log(
                'PsalmoteeData Mobile API: Activation email delivery failed. Code restoration: ' .
                ($restored ? 'successful' : 'failed')
            );
        }

        return $this->response($generic_response);
    }

    /**
     * Register a new VTU Press account through the mobile API.
     */
    public function register_account(WP_REST_Request $request)
    {
        global $wpdb;

        // Apply registration rate limiting.
        if ($this->registration_rate_limited()) {
            return $this->response(array(
                'success' => false,
                'message' => 'Too many registration attempts. Please wait and try again.',
            ), 429);
        }

        // Collect and sanitize registration information.
        $username = trim(
            sanitize_user((string) $request->get_param('username'))
        );

        $email = trim(
            sanitize_email((string) $request->get_param('email'))
        );

        $password = (string) $request->get_param('password');

        $password_confirmation = (string) $request->get_param(
            'password_confirmation'
        );

        $phone = trim(
            sanitize_text_field((string) $request->get_param('phone'))
        );

        $first_name = trim(
            sanitize_text_field((string) $request->get_param('first_name'))
        );

        $last_name = trim(
            sanitize_text_field((string) $request->get_param('last_name'))
        );

        $pin = trim(
            sanitize_text_field((string) $request->get_param('pin'))
        );

        $country = trim(
            sanitize_text_field((string) $request->get_param('country'))
        );

        $referral = trim(
            (string) ($request->get_param('referral') ?: '1')
        );

        $bvn_nin_type = trim(
            sanitize_text_field((string) $request->get_param('bvn_nin_type'))
        );

        $bvn_nin_value = trim(
            sanitize_text_field((string) $request->get_param('bvn_nin_value'))
        );

        // Required fields.
        if (
            $username === '' ||
            $email === '' ||
            $password === '' ||
            $password_confirmation === '' ||
            $phone === '' ||
            $first_name === '' ||
            $last_name === '' ||
            $pin === '' ||
            $country === ''
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please complete all required registration fields.',
            ), 400);
        }

        // Validate username.
        if (
            !validate_username($username) ||
            strlen($username) > 60
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please provide a valid username.',
            ), 400);
        }

        // Validate email.
        if (!is_email($email)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please provide a valid email address.',
            ), 400);
        }

        // Validate password.
        if (strlen($password) < 8) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your password must contain at least 8 characters.',
            ), 400);
        }

        if ($password !== $password_confirmation) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your passwords do not match.',
            ), 400);
        }

        // Validate names.
        if (
            strlen($first_name) < 3 ||
            strlen($last_name) < 3
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'First and last names must contain at least 3 characters.',
            ), 400);
        }

        // Validate transaction PIN.
        if (!preg_match('/^[1-9][0-9]{3}$/', $pin)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Your transaction PIN must contain exactly 4 digits and cannot start with zero.',
            ), 400);
        }

        // Validate referral ID.
        if (!preg_match('/^[0-9]+$/', $referral)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please provide a valid referral ID.',
            ), 400);
        }

        // Ensure VTU Press country services are available.
        if (
            !class_exists('Vtupress_Country_Manager') ||
            !method_exists('Vtupress_Country_Manager', 'enabled')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Country registration services are unavailable.',
            ), 503);
        }

        // Check whether the selected country is enabled.
        $enabled_countries = Vtupress_Country_Manager::enabled();

        if (
            !is_array($enabled_countries) ||
            !in_array($country, $enabled_countries, true)
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'This country is not enabled for registration.',
            ), 400);
        }

        // Load VTU Press general settings.
        $settings_table = $wpdb->prefix . 'vtupress_general_settings';

        $settings = $wpdb->get_row(
            "SELECT * FROM {$settings_table} ORDER BY id ASC LIMIT 1",
            ARRAY_A
        );

        if (empty($settings)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Account settings are currently unavailable.',
            ), 503);
        }

        // Check whether registration is enabled.
        $registration_enabled = $settings['enable_registration'] ?? 'yes';

        if (
            $registration_enabled !== 'yes' &&
            $registration_enabled !== 'true'
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Registration is temporarily unavailable.',
            ), 403);
        }

        // Check email verification configuration before creating accounts.
        $email_verification_enabled = (
            ($settings['enable_email_verification'] ?? 'no') === 'yes'
        );

        // Prevent incomplete account creation if VTU Press Users is unavailable.
        if (
            $email_verification_enabled &&
            !class_exists('Users')
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Account verification services are temporarily unavailable.',
            ), 503);
        }

        // Normalize phone number using the existing VTU Press helper.
        if (!function_exists('vtupress_normalize_phone')) {
            return $this->response(array(
                'success' => false,
                'message' => 'Phone number services are currently unavailable.',
            ), 503);
        }

        $normalized_phone = vtupress_normalize_phone($phone);

        $phone = $normalized_phone['local'] ?? '';

        if (!preg_match('/^[0-9]{10,15}$/', $phone)) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please provide a valid phone number.',
            ), 400);
        }

        // Check existing WordPress accounts.
        if (username_exists($username)) {
            return $this->response(array(
                'success' => false,
                'message' => 'This username is already taken.',
            ), 409);
        }

        if (email_exists($email)) {
            return $this->response(array(
                'success' => false,
                'message' => 'An account with this email already exists.',
            ), 409);
        }

        // VTU Press users table.
        $vtu_users_table = $wpdb->prefix . 'vtupress_users';

        // Check whether phone number already exists.
        $existing_phone = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT id FROM {$vtu_users_table} WHERE phone = %s LIMIT 1",
                $phone
            )
        );

        if ($existing_phone) {
            return $this->response(array(
                'success' => false,
                'message' => 'This phone number is already registered.',
            ), 409);
        }

        // Check BVN/NIN requirements configured in the manual gateway.
        $manual_gateway = class_exists('Vtupress_Gateway_Container')
            ? Vtupress_Gateway_Container::get('manual')
            : null;

        $manual_settings = $manual_gateway
            ? $manual_gateway->get_settings()
            : array();

        $request_bvn_nin = (
            $manual_settings['request_bvn_nin'] ?? 'no'
        ) === 'yes';

        $request_bvn_nin_required = (
            $manual_settings['request_bvn_nin_required'] ?? 'no'
        ) === 'yes';

        $bvn = '';
        $nin = '';

        if ($request_bvn_nin && $bvn_nin_value !== '') {

            if ($bvn_nin_type === 'bvn') {
                $bvn = $bvn_nin_value;

            } elseif ($bvn_nin_type === 'nin') {
                $nin = $bvn_nin_value;

            } else {
                return $this->response(array(
                    'success' => false,
                    'message' => 'Please select whether you are providing a BVN or NIN.',
                ), 400);
            }
        }

        if (
            $request_bvn_nin &&
            $request_bvn_nin_required &&
            $bvn === '' &&
            $nin === ''
        ) {
            return $this->response(array(
                'success' => false,
                'message' => 'Please provide your BVN or NIN to complete registration.',
            ), 400);
        }

        // Resolve referral account.
        $referrer_id = 1;

        if ((int) $referral !== 1) {

            $referrer_exists = $wpdb->get_var(
                $wpdb->prepare(
                    "SELECT id FROM {$vtu_users_table} WHERE id = %d LIMIT 1",
                    (int) $referral
                )
            );

            if ($referrer_exists) {
                $referrer_id = (int) $referrer_exists;
            }
        }

        // Create WordPress account.
        $userdata = array(
            'user_login' => $username,
            'user_email' => $email,
            'user_pass' => $password,
            'first_name' => $first_name,
            'last_name' => $last_name,
        );

        $wp_user_id = wp_insert_user($userdata);

        if (is_wp_error($wp_user_id)) {
            return $this->response(array(
                'success' => false,
                'message' => $wp_user_id->get_error_message(),
            ), 400);
        }

        // Generate VTU Press API key.
        $api_key = 'vtu-' . wp_generate_password(32, false, false);

        // Create VTU Press account record.
        $new_user_data = array(
            'userId' => $wp_user_id,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'email_verified' => 'false',
            'plan' => 'customer',
            'apikey' => $api_key,
            'phone' => $phone,
            'pin' => $pin,
            'balance' => 0,
            'referral_rewards' => 0,
            'referrer_id' => $referrer_id,
            'referrers' => '[]',
            'indirect_referrers' => '[]',
            'other_referrers' => '[]',
            'beneficiaries' => '',
            'fix_version' => '1.0',
            'all_plans' => 'customer',
            'run_code' => random_int(1000, 9999),
            'set_country' => $country,
            'bvn' => $bvn,
            'nin' => $nin,
        );

        $inserted = $wpdb->insert(
            $vtu_users_table,
            $new_user_data
        );

        if (!$inserted) {

            // Remove the WordPress account if VTU profile creation fails.
            require_once ABSPATH . 'wp-admin/includes/user.php';

            wp_delete_user($wp_user_id);

            return $this->response(array(
                'success' => false,
                'message' => 'Unable to create your VTU Press account. Please try again.',
            ), 500);
        }

        $vtu_user_id = (int) $wpdb->insert_id;

        $email_sent = false;

        if ($email_verification_enabled) {

            try {
                $activation_code = (string) random_int(10000, 99999);
            } catch (Exception $exception) {

                $wpdb->delete(
                    $vtu_users_table,
                    array('id' => $vtu_user_id),
                    array('%d')
                );

                require_once ABSPATH . 'wp-admin/includes/user.php';

                wp_delete_user($wp_user_id);

                return $this->response(array(
                    'success' => false,
                    'message' => 'Unable to prepare account verification. Please try again.',
                ), 500);
            }

            // Store activation code using the VTU Press record ID.
            $users_api = new Users();

            $code_saved = $users_api->update(
                $vtu_user_id,
                array(
                    'reset_code' => $activation_code,
                )
            );

            if (!$code_saved) {

                $wpdb->delete(
                    $vtu_users_table,
                    array('id' => $vtu_user_id),
                    array('%d')
                );

                require_once ABSPATH . 'wp-admin/includes/user.php';

                wp_delete_user($wp_user_id);

                return $this->response(array(
                    'success' => false,
                    'message' => 'Unable to prepare email verification. Please try again.',
                ), 500);
            }

            // Use the existing VTU Press email system.
            if (
                class_exists('Vtupress_Mail')
            ) {
                $mailer = new Vtupress_Mail();

                $email_sent = (bool) $mailer->sendMail(
                    $email,
                    'Account Verification',
                    'Your account activation code is <strong>' .
                        esc_html($activation_code) .
                        '</strong>.'
                );
            }
        }

        // Update the referral tree.
        if ($referrer_id !== 1) {

            $upline_1 = $wpdb->get_row(
                $wpdb->prepare(
                    "SELECT id, referrers, referrer_id
                    FROM {$vtu_users_table}
                    WHERE id = %d",
                    $referrer_id
                )
            );

            if ($upline_1) {

                $level_1_refs = json_decode(
                    $upline_1->referrers,
                    true
                ) ?: array();

                $level_1_refs[] = $vtu_user_id;

                $wpdb->update(
                    $vtu_users_table,
                    array(
                        'referrers' => wp_json_encode($level_1_refs),
                    ),
                    array(
                        'id' => $upline_1->id,
                    )
                );

                // Level 2.
                $upline_2_id = (int) $upline_1->referrer_id;

                if ($upline_2_id && $upline_2_id !== 1) {

                    $upline_2 = $wpdb->get_row(
                        $wpdb->prepare(
                            "SELECT id, indirect_referrers, referrer_id
                            FROM {$vtu_users_table}
                            WHERE id = %d",
                            $upline_2_id
                        )
                    );

                    if ($upline_2) {

                        $level_2_refs = json_decode(
                            $upline_2->indirect_referrers,
                            true
                        ) ?: array();

                        $level_2_refs[] = $vtu_user_id;

                        $wpdb->update(
                            $vtu_users_table,
                            array(
                                'indirect_referrers' => wp_json_encode($level_2_refs),
                            ),
                            array(
                                'id' => $upline_2->id,
                            )
                        );

                        // Level 3.
                        $upline_3_id = (int) $upline_2->referrer_id;

                        if ($upline_3_id && $upline_3_id !== 1) {

                            $upline_3 = $wpdb->get_row(
                                $wpdb->prepare(
                                    "SELECT id, other_referrers
                                    FROM {$vtu_users_table}
                                    WHERE id = %d",
                                    $upline_3_id
                                )
                            );

                            if ($upline_3) {

                                $level_3_refs = json_decode(
                                    $upline_3->other_referrers,
                                    true
                                ) ?: array();

                                $level_3_refs[] = $vtu_user_id;

                                $wpdb->update(
                                    $vtu_users_table,
                                    array(
                                        'other_referrers' => wp_json_encode($level_3_refs),
                                    ),
                                    array(
                                        'id' => $upline_3->id,
                                    )
                                );
                            }
                        }
                    }
                }
            }
        }

        // Create virtual account where the selected gateway supports it.
        if (class_exists('Vtupress_Gateway_Container')) {

            $gateways = Vtupress_Gateway_Container::for_country($country);

            if (is_iterable($gateways)) {

                foreach ($gateways as $gateway) {

                    if (
                        property_exists($gateway, 'create_on_reg') &&
                        $gateway->create_on_reg === true
                    ) {
                        $gateway_settings = $gateway->get_settings();

                        $account_on_registration = (
                            $gateway_settings['account_on_registration'] ?? 'no'
                        );

                        if (
                            $account_on_registration === 'yes' &&
                            method_exists($gateway, 'create_virtual_account')
                        ) {
                            try {
                                $gateway->create_virtual_account($wp_user_id);
                            } catch (Throwable $exception) {
                                // Virtual account creation must not invalidate registration.
                            }
                        }
                    }
                }
            }
        }

        // wp_insert_user() already fires the WordPress user_register action.
        // Do not fire it manually a second time.

        // Clear registration rate limit after successful account creation.
        $this->clear_registration_rate_limit();

        // Return registration result.
        if ($email_verification_enabled) {

            if ($email_sent) {

                return $this->response(array(
                    'success' => true,
                    'message' => 'Your account has been created. Please check your email for your activation code.',
                    'verification_required' => true,
                    'email_sent' => true,
                    'user' => array(
                        'username' => $username,
                        'email' => $email,
                    ),
                ), 201);
            }

            // Account exists, but the email system did not confirm sending.
            return $this->response(array(
                'success' => true,
                'message' => 'Your account was created, but we could not send the activation email. Please contact support for assistance.',
                'verification_required' => true,
                'email_sent' => false,
                'user' => array(
                    'username' => $username,
                    'email' => $email,
                ),
            ), 201);
        }

        return $this->response(array(
            'success' => true,
            'message' => 'Your account has been created successfully. You can now sign in.',
            'verification_required' => false,
            'email_sent' => false,
            'user' => array(
                'username' => $username,
                'email' => $email,
            ),
        ), 201);
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