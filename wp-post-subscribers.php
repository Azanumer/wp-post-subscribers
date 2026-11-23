<?php
/**
 * Plugin Name: WP Post Subscribers
 * Plugin URI: https://github.com/Azanumer/wp-post-subscribers
 * Description: Let visitors subscribe by email and get notified when a new post is published. Double opt-in, one-click unsubscribe, zero plugins required.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: Azan Umer
 * Author URI: https://azanumer.cv
 * License: MIT
 * Text Domain: wp-post-subscribers
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WPS_VERSION', '1.0.0' );
define( 'WPS_TABLE', 'wps_subscribers' );

/**
 * Create the subscribers table on activation.
 */
function wps_activate() {
    global $wpdb;

    $table   = $wpdb->prefix . WPS_TABLE;
    $charset = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE {$table} (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        email varchar(191) NOT NULL,
        token varchar(64) NOT NULL,
        status varchar(20) NOT NULL DEFAULT 'pending',
        created_at datetime NOT NULL,
        confirmed_at datetime DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY email (email),
        KEY token (token),
        KEY status (status)
    ) {$charset};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta( $sql );

    add_option( 'wps_post_types', array( 'post' ) );
    add_option( 'wps_from_name', get_bloginfo( 'name' ) );
    add_option( 'wps_notify_subject', __( 'New post: {title}', 'wp-post-subscribers' ) );
}
register_activation_hook( __FILE__, 'wps_activate' );

/**
 * Signed token for confirm/unsubscribe links: HMAC of email + action.
 * Stateless, so links keep working even if the token column is regenerated.
 */
function wps_signed_token( $email, $action ) {
    return hash_hmac( 'sha256', strtolower( trim( $email ) ) . '|' . $action, wp_salt() );
}

/**
 * Confirm / unsubscribe endpoint (?wps_action=confirm|unsubscribe&wps_email=...&wps_token=...).
 */
function wps_handle_action() {
    if ( empty( $_GET['wps_action'] ) || empty( $_GET['wps_email'] ) || empty( $_GET['wps_token'] ) ) {
        return;
    }

    $action = sanitize_key( $_GET['wps_action'] );
    if ( ! in_array( $action, array( 'confirm', 'unsubscribe' ), true ) ) {
        return;
    }

    $email = sanitize_email( wp_unslash( $_GET['wps_email'] ) );
    $token = sanitize_text_field( wp_unslash( $_GET['wps_token'] ) );

    if ( ! hash_equals( wps_signed_token( $email, $action ), $token ) ) {
        wp_die( esc_html__( 'This link is invalid.', 'wp-post-subscribers' ), 403 );
    }

    global $wpdb;
    $table = $wpdb->prefix . WPS_TABLE;

    if ( 'confirm' === $action ) {
        $wpdb->update(
            $table,
            array(
                'status'       => 'confirmed',
                'confirmed_at' => current_time( 'mysql' ),
            ),
            array( 'email' => $email, 'status' => 'pending' ),
            array( '%s', '%s' ),
            array( '%s', '%s' )
        );
        $message = __( 'Thank you! Your subscription is confirmed — you will hear about new posts.', 'wp-post-subscribers' );
    } else {
        $wpdb->delete( $table, array( 'email' => $email ), array( '%s' ) );
        $message = __( 'You have been unsubscribed. Sorry to see you go!', 'wp-post-subscribers' );
    }

    wp_die(
        '<p>' . esc_html( $message ) . '</p><p><a href="' . esc_url( home_url( '/' ) ) . '">' . esc_html__( 'Back to the site', 'wp-post-subscribers' ) . '</a></p>',
        esc_html__( 'Subscription', 'wp-post-subscribers' ),
        array( 'response' => 200 )
    );
}
add_action( 'init', 'wps_handle_action' );

/**
 * Subscribe form shortcode: [subscribe_form]
 * Nonce + honeypot + 3-second timing trap (same anti-spam pattern as the
 * site's other form plugins).
 */
function wps_subscribe_form_shortcode() {
    $output = '';

    if ( isset( $_GET['wps_subscribed'] ) && '1' === $_GET['wps_subscribed'] ) {
        $output .= '<p class="wps-message">' . esc_html__( 'Check your inbox — we sent a confirmation email.', 'wp-post-subscribers' ) . '</p>';
    }
    if ( isset( $_GET['wps_error'] ) && '1' === $_GET['wps_error'] ) {
        $output .= '<p class="wps-message wps-error">' . esc_html__( 'That email address does not look valid. Please try again.', 'wp-post-subscribers' ) . '</p>';
    }

    $output .= '<form method="post" class="wps-subscribe-form">';
    $output .= wp_nonce_field( 'wps_subscribe', 'wps_nonce', true, false );
    $output .= '<input type="email" name="wps_email" placeholder="' . esc_attr__( 'Your email address', 'wp-post-subscribers' ) . '" required />';
    // Honeypot: hidden from humans, bots fill it.
    $output .= '<input type="text" name="wps_website" value="" style="display:none" tabindex="-1" autocomplete="off" />';
    $output .= '<input type="hidden" name="wps_started" value="' . time() . '" />';
    $output .= '<button type="submit" name="wps_subscribe_submit">' . esc_html__( 'Subscribe', 'wp-post-subscribers' ) . '</button>';
    $output .= '</form>';

    return $output;
}
add_shortcode( 'subscribe_form', 'wps_subscribe_form_shortcode' );

/**
 * Handle the subscribe form POST (runs on init, before headers).
 */
function wps_handle_subscribe() {
    if ( empty( $_POST['wps_subscribe_submit'] ) ) {
        return;
    }

    $redirect = remove_query_arg( array( 'wps_subscribed', 'wps_error' ) );

    if ( ! isset( $_POST['wps_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wps_nonce'] ) ), 'wps_subscribe' ) ) {
        wp_safe_redirect( add_query_arg( 'wps_error', '1', $redirect ) );
        exit;
    }

    // Honeypot filled or submitted faster than 3 seconds: silently "succeed".
    $started = (int) ( $_POST['wps_started'] ?? 0 );
    if ( ! empty( $_POST['wps_website'] ) || $started <= 0 || ( time() - $started ) < 3 ) {
        wp_safe_redirect( add_query_arg( 'wps_subscribed', '1', $redirect ) );
        exit;
    }

    $email = sanitize_email( wp_unslash( $_POST['wps_email'] ?? '' ) );
    if ( ! is_email( $email ) ) {
        wp_safe_redirect( add_query_arg( 'wps_error', '1', $redirect ) );
        exit;
    }

    global $wpdb;
    $table = $wpdb->prefix . WPS_TABLE;

    $existing = $wpdb->get_var( $wpdb->prepare( "SELECT status FROM {$table} WHERE email = %s", $email ) );
    if ( 'confirmed' === $existing ) {
        // Already subscribed — same success message, no duplicate email.
        wp_safe_redirect( add_query_arg( 'wps_subscribed', '1', $redirect ) );
        exit;
    }

    $token = wp_generate_password( 32, false );
    if ( 'pending' === $existing ) {
        $wpdb->update( $table, array( 'token' => $token ), array( 'email' => $email ), array( '%s' ), array( '%s' ) );
    } else {
        $wpdb->insert(
            $table,
            array(
                'email'      => $email,
                'token'      => $token,
                'status'     => 'pending',
                'created_at' => current_time( 'mysql' ),
            ),
            array( '%s', '%s', '%s', '%s' )
        );
    }

    $confirm_url = add_query_arg(
        array(
            'wps_action' => 'confirm',
            'wps_email'  => rawurlencode( $email ),
            'wps_token'  => wps_signed_token( $email, 'confirm' ),
        ),
        home_url( '/' )
    );

    /* translators: %s confirmation link */
    $body = sprintf(
        __( "Hi!\n\nPlease confirm your subscription to %1\$s by clicking this link:\n%2\$s\n\nIf you did not ask for this, just ignore this email.", 'wp-post-subscribers' ),
        get_bloginfo( 'name' ),
        $confirm_url
    );

    wp_mail(
        $email,
        sprintf(
            /* translators: %s site name */
            __( 'Confirm your subscription to %s', 'wp-post-subscribers' ),
            get_bloginfo( 'name' )
        ),
        $body
    );

    wp_safe_redirect( add_query_arg( 'wps_subscribed', '1', $redirect ) );
    exit;
}
add_action( 'init', 'wps_handle_subscribe' );

/**
 * Notify confirmed subscribers when a post is first published.
 * transition_post_status fires for updates too — only brand-new publishes
 * (old status not 'publish') trigger the email.
 */
function wps_notify_on_publish( $new_status, $old_status, $post ) {
    if ( 'publish' !== $new_status || 'publish' === $old_status ) {
        return;
    }

    $post_types = get_option( 'wps_post_types', array( 'post' ) );
    if ( ! in_array( $post->post_type, (array) $post_types, true ) ) {
        return;
    }

    // Never notify for password-protected posts.
    if ( '' !== $post->post_password ) {
        return;
    }

    global $wpdb;
    $table  = $wpdb->prefix . WPS_TABLE;
    $emails = $wpdb->get_col( "SELECT email FROM {$table} WHERE status = 'confirmed' ORDER BY id ASC" );
    if ( empty( $emails ) ) {
        return;
    }

    $subject = str_replace( '{title}', $post->post_title, get_option( 'wps_notify_subject', __( 'New post: {title}', 'wp-post-subscribers' ) ) );
    $subject = apply_filters( 'wps_notify_subject', $subject, $post );

    $excerpt = has_excerpt( $post->ID ) ? get_the_excerpt( $post ) : wp_trim_words( wp_strip_all_tags( $post->post_content ), 55 );

    foreach ( $emails as $email ) {
        $unsubscribe_url = add_query_arg(
            array(
                'wps_action' => 'unsubscribe',
                'wps_email'  => rawurlencode( $email ),
                'wps_token'  => wps_signed_token( $email, 'unsubscribe' ),
            ),
            home_url( '/' )
        );

        /* translators: 1: post title, 2: excerpt, 3: post URL, 4: unsubscribe URL */
        $body = sprintf(
            __( "%1\$s\n\n%2\$s\n\nRead it here: %3\$s\n\n---\nYou are receiving this because you subscribed on %4\$s.\nUnsubscribe: %5\$s", 'wp-post-subscribers' ),
            $post->post_title,
            $excerpt,
            get_permalink( $post ),
            get_bloginfo( 'name' ),
            $unsubscribe_url
        );

        wp_mail( $email, $subject, $body );
    }
}
add_action( 'transition_post_status', 'wps_notify_on_publish', 10, 3 );

/**
 * Tools page: subscriber list + settings.
 */
function wps_admin_page() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( esc_html__( 'You do not have permission to access this page.', 'wp-post-subscribers' ) );
    }

    global $wpdb;
    $table = $wpdb->prefix . WPS_TABLE;

    if ( isset( $_POST['wps_save_settings'] ) && check_admin_referer( 'wps_settings' ) ) {
        $types = array_intersect(
            array_map( 'sanitize_key', (array) ( $_POST['wps_post_types'] ?? array() ) ),
            get_post_types( array( 'public' => true ) )
        );
        update_option( 'wps_post_types', array_values( $types ) );
        update_option( 'wps_from_name', sanitize_text_field( $_POST['wps_from_name'] ?? '' ) );
        update_option( 'wps_notify_subject', sanitize_text_field( $_POST['wps_notify_subject'] ?? '' ) );
        echo '<div class="notice notice-success"><p>' . esc_html__( 'Settings saved.', 'wp-post-subscribers' ) . '</p></div>';
    }

    if ( isset( $_POST['wps_delete'] ) && check_admin_referer( 'wps_delete' ) ) {
        $wpdb->delete( $table, array( 'id' => (int) $_POST['wps_delete'] ), array( '%d' ) );
        echo '<div class="notice notice-success"><p>' . esc_html__( 'Subscriber removed.', 'wp-post-subscribers' ) . '</p></div>';
    }

    $total     = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
    $confirmed = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE status = 'confirmed'" );
    $page      = max( 1, (int) ( $_GET['paged'] ?? 1 ) );
    $per_page  = 50;
    $offset    = ( $page - 1 ) * $per_page;
    $rows      = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", $per_page, $offset ) );
    $post_types = get_post_types( array( 'public' => true ), 'objects' );
    $selected   = get_option( 'wps_post_types', array( 'post' ) );
    ?>
    <div class="wrap">
        <h1><?php esc_html_e( 'Post Subscribers', 'wp-post-subscribers' ); ?></h1>
        <p>
            <?php
            printf(
                /* translators: %1$d confirmed, %2$d total */
                esc_html__( '%1$d confirmed subscribers out of %2$d total.', 'wp-post-subscribers' ),
                $confirmed,
                $total
            );
            ?>
            <?php esc_html_e( 'Add the subscribe form anywhere with the [subscribe_form] shortcode.', 'wp-post-subscribers' ); ?>
        </p>

        <h2><?php esc_html_e( 'Settings', 'wp-post-subscribers' ); ?></h2>
        <form method="post">
            <?php wp_nonce_field( 'wps_settings' ); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e( 'Notify for', 'wp-post-subscribers' ); ?></th>
                    <td>
                        <?php foreach ( $post_types as $pt ) : ?>
                            <label>
                                <input type="checkbox" name="wps_post_types[]" value="<?php echo esc_attr( $pt->name ); ?>" <?php checked( in_array( $pt->name, (array) $selected, true ) ); ?> />
                                <?php echo esc_html( $pt->label ); ?>
                            </label><br />
                        <?php endforeach; ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><label for="wps_notify_subject"><?php esc_html_e( 'Email subject', 'wp-post-subscribers' ); ?></label></th>
                    <td>
                        <input type="text" id="wps_notify_subject" name="wps_notify_subject" class="regular-text" value="<?php echo esc_attr( get_option( 'wps_notify_subject', '' ) ); ?>" />
                        <p class="description"><?php esc_html_e( '{title} is replaced with the post title.', 'wp-post-subscribers' ); ?></p>
                    </td>
                </tr>
            </table>
            <?php submit_button( __( 'Save settings', 'wp-post-subscribers' ), 'primary', 'wps_save_settings' ); ?>
        </form>

        <h2><?php esc_html_e( 'Subscribers', 'wp-post-subscribers' ); ?></h2>
        <table class="widefat striped">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Email', 'wp-post-subscribers' ); ?></th>
                    <th><?php esc_html_e( 'Status', 'wp-post-subscribers' ); ?></th>
                    <th><?php esc_html_e( 'Subscribed', 'wp-post-subscribers' ); ?></th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ( $rows as $row ) : ?>
                    <tr>
                        <td><?php echo esc_html( $row->email ); ?></td>
                        <td><?php echo esc_html( $row->status ); ?></td>
                        <td><?php echo esc_html( $row->created_at ); ?></td>
                        <td>
                            <form method="post" style="display:inline">
                                <?php wp_nonce_field( 'wps_delete' ); ?>
                                <input type="hidden" name="wps_delete" value="<?php echo (int) $row->id; ?>" />
                                <?php submit_button( __( 'Delete', 'wp-post-subscribers' ), 'small', 'wps_delete_submit', false ); ?>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                <?php if ( empty( $rows ) ) : ?>
                    <tr><td colspan="4"><?php esc_html_e( 'No subscribers yet.', 'wp-post-subscribers' ); ?></td></tr>
                <?php endif; ?>
            </tbody>
        </table>
        <?php
        echo paginate_links(
            array(
                'base'    => add_query_arg( 'paged', '%#%' ),
                'format'  => '',
                'total'   => (int) ceil( $total / $per_page ),
                'current' => $page,
            )
        );
        ?>
    </div>
    <?php
}

function wps_register_menu() {
    add_management_page(
        __( 'Post Subscribers', 'wp-post-subscribers' ),
        __( 'Post Subscribers', 'wp-post-subscribers' ),
        'manage_options',
        'wp-post-subscribers',
        'wps_admin_page'
    );
}
add_action( 'admin_menu', 'wps_register_menu' );
