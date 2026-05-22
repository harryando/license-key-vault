<?php
/**
 * Plugin Name: License Key Vault
 * Description: Auto-save API keys, license keys, tokens, and secrets locally for admins only.
 * Version: 2.0
 * Author: Mas Ando & ChatGPT
 */

if (!defined('ABSPATH')) {
    exit;
}

class Universal_Admin_Key_Vault_PRO {

    private $option_name = 'uakv_saved_keys';
    private $webhook_option = 'uakv_webhook_url';

    public function __construct() {

        if (!is_admin()) {
            return;
        }

        add_action('admin_init', [$this, 'capture_keys']);
        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'assets']);
    }

    /**
     * Detect plugin group
     */
    private function detect_plugin_group($field) {

        $field = strtolower($field);

        $groups = [

            'ACF Pro' => ['acf'],
            'Elementor Pro' => ['elementor'],
            'WP Rocket' => ['rocket'],
            'Twitter/X API' => ['twitter', 'x_api', 'consumer', 'access_token'],
            'OpenAI' => ['openai', 'chatgpt'],
            'Stripe' => ['stripe'],
            'Mailchimp' => ['mailchimp'],
            'Discord' => ['discord'],
            'Cloudflare' => ['cloudflare'],
        ];

        foreach ($groups as $group => $keywords) {

            foreach ($keywords as $keyword) {

                if (strpos($field, $keyword) !== false) {
                    return $group;
                }
            }
        }

        return 'Other';
    }

    /**
     * Encrypt
     */
    private function encrypt($data) {

        $key = wp_salt('auth');

        return openssl_encrypt(
            $data,
            'AES-256-CBC',
            $key,
            0,
            substr(hash('sha256', $key), 0, 16)
        );
    }

    /**
     * Decrypt
     */
    private function decrypt($data) {

        $key = wp_salt('auth');

        return openssl_decrypt(
            $data,
            'AES-256-CBC',
            $key,
            0,
            substr(hash('sha256', $key), 0, 16)
        );
    }

    /**
     * Send webhook
     */
    private function send_webhook($field) {

        $url = get_option($this->webhook_option);

        if (empty($url)) {
            return;
        }

        wp_remote_post($url, [
            'timeout' => 10,
            'body' => [
                'message' => 'New key stored: ' . $field,
                'site'    => home_url(),
                'time'    => current_time('mysql'),
            ]
        ]);
    }

    /**
     * Capture keys
     */
    public function capture_keys() {

        if (!current_user_can('manage_options')) {
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            return;
        }

        if (empty($_POST)) {
            return;
        }

        $saved = get_option($this->option_name, []);

        $keywords = [
            'key',
            'token',
            'secret',
            'license',
            'licence',
            'api',
            'consumer',
            'bearer',
            'auth',
            'access'
        ];

        foreach ($_POST as $field => $value) {

            if (is_array($value) || is_object($value)) {
                continue;
            }

            if (!is_string($value)) {
                continue;
            }

            $field_lower = strtolower($field);

            $matched = false;

            foreach ($keywords as $keyword) {

                if (strpos($field_lower, $keyword) !== false) {
                    $matched = true;
                    break;
                }
            }

            if (!$matched) {
                continue;
            }

            $clean = trim(wp_unslash($value));

            if (strlen($clean) < 6) {
                continue;
            }

            if (filter_var($clean, FILTER_VALIDATE_URL)) {
                continue;
            }

            $exists = isset($saved[$field]);

            $saved[$field] = [
                'value'   => $this->encrypt($clean),
                'updated' => current_time('mysql'),
                'group'   => $this->detect_plugin_group($field),
            ];

            if (!$exists) {
                $this->send_webhook($field);
            }
        }

        update_option($this->option_name, $saved, false);
    }

    /**
     * Admin menu
     */
    public function admin_menu() {

        add_menu_page(
            'Key Vault',
            'Key Vault',
            'manage_options',
            'universal-key-vault',
            [$this, 'render_page'],
            'dashicons-shield',
            80
        );
    }

    /**
     * Assets
     */
    public function assets($hook) {

        if ($hook !== 'toplevel_page_universal-key-vault') {
            return;
        }

        wp_add_inline_script('jquery', "
            document.addEventListener('DOMContentLoaded', function () {

                // Copy
                document.querySelectorAll('.uakv-copy').forEach(function(btn) {

                    btn.addEventListener('click', function() {

                        const target = document.getElementById(this.dataset.target);

                        navigator.clipboard.writeText(target.value);

                        this.innerText = 'Copied!';

                        setTimeout(() => {
                            this.innerText = 'Copy';
                        }, 1500);
                    });
                });

                // Toggle
                document.querySelectorAll('.uakv-toggle').forEach(function(btn){

                    btn.addEventListener('click', function(){

                        const target = document.getElementById(this.dataset.target);

                        if (target.type === 'password') {
                            target.type = 'text';
                            this.innerText = 'Hide';
                        } else {
                            target.type = 'password';
                            this.innerText = 'Show';
                        }
                    });
                });

                // Reveal all
                document.getElementById('uakv-reveal-all').addEventListener('click', function(){

                    document.querySelectorAll('.uakv-input').forEach(function(input){
                        input.type = 'text';
                    });
                });

                // Hide all
                document.getElementById('uakv-hide-all').addEventListener('click', function(){

                    document.querySelectorAll('.uakv-input').forEach(function(input){
                        input.type = 'password';
                    });
                });

            });
        ");
    }

    /**
     * Export
     */
    private function export_backup() {

        if (!isset($_GET['uakv_export'])) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $data = get_option($this->option_name, []);

        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename=key-vault-backup.json');

        echo wp_json_encode($data);

        exit;
    }

    /**
     * Render page
     */
    public function render_page() {

        $this->export_backup();

        if (!current_user_can('manage_options')) {
            return;
        }

        // Save webhook
        if (isset($_POST['uakv_webhook'])) {

            update_option(
                $this->webhook_option,
                esc_url_raw($_POST['uakv_webhook'])
            );

            echo '<div class="updated"><p>Webhook saved.</p></div>';
        }

        // Import
        if (!empty($_FILES['uakv_import']['tmp_name'])) {

            $json = file_get_contents($_FILES['uakv_import']['tmp_name']);

            $data = json_decode($json, true);

            if (is_array($data)) {

                update_option($this->option_name, $data);

                echo '<div class="updated"><p>Backup imported.</p></div>';
            }
        }

        $saved = get_option($this->option_name, []);

        $grouped = [];

        foreach ($saved as $field => $data) {

            $group = $data['group'] ?? 'Other';

            $grouped[$group][$field] = $data;
        }

        ?>

        <div class="wrap">

            <h1>Universal Admin Key Vault PRO</h1>

            <p>
                Automatically stores detected API keys, tokens, secrets, and licenses locally.
            </p>

            <p>
                <button class="button" id="uakv-reveal-all">
                    Reveal All
                </button>

                <button class="button" id="uakv-hide-all">
                    Hide All
                </button>

                <a href="?page=universal-key-vault&uakv_export=1"
                   class="button button-primary">
                    Export Backup
                </a>
            </p>

            <hr>

            <h2>Webhook Notification</h2>

            <form method="post">

                <input
                    type="url"
                    name="uakv_webhook"
                    value="<?php echo esc_attr(get_option($this->webhook_option)); ?>"
                    placeholder="https://discord.com/api/webhooks/..."
                    style="width:500px;"
                >

                <button class="button button-primary">
                    Save Webhook
                </button>

            </form>

            <hr>

            <h2>Import Backup</h2>

            <form method="post" enctype="multipart/form-data">

                <input type="file" name="uakv_import">

                <button class="button">
                    Import Backup
                </button>

            </form>

            <hr>

            <?php foreach ($grouped as $group => $items) : ?>

                <h2><?php echo esc_html($group); ?></h2>

                <table class="widefat striped" style="margin-bottom:40px;">

                    <thead>
                        <tr>
                            <th style="width:300px;">Field</th>
                            <th>Stored Value</th>
                            <th style="width:180px;">Updated</th>
                            <th style="width:180px;">Action</th>
                        </tr>
                    </thead>

                    <tbody>

                    <?php foreach ($items as $field => $data) :

                        $decoded = $this->decrypt($data['value']);

                        $field_id = 'uakv_' . md5($field);

                    ?>

                        <tr>

                            <td>
                                <strong>
                                    <?php echo esc_html($field); ?>
                                </strong>
                            </td>

                            <td>

                                <input
                                    type="password"
                                    readonly
                                    class="uakv-input"
                                    id="<?php echo esc_attr($field_id); ?>"
                                    value="<?php echo esc_attr($decoded); ?>"
                                    style="width:100%;"
                                >

                            </td>

                            <td>
                                <?php echo esc_html($data['updated']); ?>
                            </td>

                            <td>

                                <button
                                    type="button"
                                    class="button uakv-toggle"
                                    data-target="<?php echo esc_attr($field_id); ?>"
                                >
                                    Show
                                </button>

                                <button
                                    type="button"
                                    class="button button-primary uakv-copy"
                                    data-target="<?php echo esc_attr($field_id); ?>"
                                >
                                    Copy
                                </button>

                            </td>

                        </tr>

                    <?php endforeach; ?>

                    </tbody>

                </table>

            <?php endforeach; ?>

        </div>

        <?php
    }
}

new Universal_Admin_Key_Vault_PRO();
