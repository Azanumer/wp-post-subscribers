<?php
/**
 * Uninstall WP Post Subscribers.
 *
 * Drops the subscribers table and removes the plugin's options.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

global $wpdb;

$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}wps_subscribers" ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

delete_option( 'wps_post_types' );
delete_option( 'wps_from_name' );
delete_option( 'wps_notify_subject' );
