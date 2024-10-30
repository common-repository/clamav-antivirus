<?php
/*
Plugin Name: ClamAV Daemon Antivirus
Plugin URI: https://www.web-match.nl
Description: Scans uploaded files by passing them to clamd. This plugins requires a running clamd daemon on localhost for now and it also usable in chroot environments.
Version: 0.1
Author: Stephan van de Haar
Author URI: https://www.web-match.nl
License: GPL
*/

ClamAV_Antivirus::init();

/**
 * Scan for virusses using ClamAV daemon
 *
 * ClamAVDaemon implementation is borrowed from the Drupal AntiVirus project.
 *
 * @see http://drupalcode.org/project/antivirus.git
 * @author Stephan van de Haar
 */
class ClamAV_Antivirus {
	/**
	 * Init
	 */
	static public function init() {
		add_action('wp_handle_upload_prefilter', array(get_class(), 'scan'));
	}

	/**
	 * Scan a file for virusses
	 *
	 * @param string $file
	 */
	static public function scan($file) {
		// require antivir libs
		require_once(__DIR__.'/lib/AntivirusScanner.php');
		require_once(__DIR__.'/lib/ClamAVDaemonScanner.php');

		$tmpfile = $file['tmp_name'];
		$debug = false;

		$clamav = new ClamAVDaemonScanner;
		$result = $clamav->scan($tmpfile, null, $debug);

		switch ($result) {
			// if an error occured, block the operation
			case ANTIVIRUS_CLAMAVDAEMON_SCAN_UNCHECKED:
			case ANTIVIRUS_CLAMAVDAEMON_SCAN_ERROR:
			case ANTIVIRUS_CLAMAVDAEMON_SCAN_FOUND:

				$template = file_get_contents(__DIR__.'/lib/response.htm');
				$msg = $clamav->getLastMessage();
				$msg = str_replace($file['tmp_name'], sprintf('"%s"', $file['name']), $msg);

				echo str_replace(
						array('%file', '%msg'),
						array($file['name'], $msg),
						$template
				);
				exit;

			case ANTIVIRUS_CLAMAVDAEMON_SCAN_OK:
				return $file;

		}
	}

}

