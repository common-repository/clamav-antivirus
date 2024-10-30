<?php

/**
 * @file
 *   Definition of ClamAVDaemonScanner.
 */

/**
 * Denotes that a virus has been found in a file.
 */
define('ANTIVIRUS_CLAMAVDAEMON_SCAN_OK', 0x0);

/**
 * Denotes that a virus has been found in a file.
 */
define('ANTIVIRUS_CLAMAVDAEMON_SCAN_FOUND', 0x1);

/**
 * Denotes that an error was found while scanning a file.
 */
define('ANTIVIRUS_CLAMAVDAEMON_SCAN_ERROR', 0x2);

/**
 * Denotes that the scan could not be completed.
 */
define('ANTIVIRUS_CLAMAVDAEMON_SCAN_UNCHECKED', 0x3);

/**
 * The default host for clamd.
 */
define('ANTIVIRUS_CLAMAVDAEMON_DEFAULT_HOST', 'localhost');

/**
 * The default port for clamd.
 */
define('ANTIVIRUS_CLAMAVDAEMON_DEFAULT_PORT', '3310');

/**
 * Implements the Clam AntiVirus scanner for a daemon process.
 *
 * @ingroup antivirus_scanners
 */
class ClamAVDaemonScanner extends AntivirusScanner {

  public function __construct() {
    $this->name = 'clamavdaemon';
  }

  /**
   * Implementation of AntivirusScanner::version().
   */
  public function versionFlags() {
    return array('--version' => '');
  }

  /**
   * Implementation of AntivirusScanner:getPath().
   */
  public function getPath() {
    return 'none';
  }

  /**
   * Implementation of AntivirusScanner::scan().
   */
  public function scan($file, $options = array(), $debug = FALSE) {
    $settings = variable_get('antivirus_settings_clamavdaemon', array());

    $flags = $this->getFlags();
    if (isset($options['flags'])) {
      $flags += $options['flags'];
    }
    array_push($flags, escapeshellarg($file));

    $host = isset($settings['host']) ? $settings['host'] : ANTIVIRUS_CLAMAVDAEMON_DEFAULT_HOST;
    $port = isset($settings['port']) ? $settings['port'] : ANTIVIRUS_CLAMAVDAEMON_DEFAULT_PORT;
  
    // try to open a socket to clamav
    $handler = ($host && $port) ? @fsockopen($host, $port) : FALSE;
  
    if (!$handler) {
      watchdog('antivirus', 'The clamav module can not connect to the clamav daemon.  The uploaded file %file could not be scanned.', array('%file' => $file), WATCHDOG_WARNING);
      return ANTIVIRUS_CLAMAVDAEMON_SCAN_UNCHECKED;
    }
  
    // Request a scan from the daemon.
    $filehandler = fopen($file, 'r');
    if ($filehandler) {
      // Open a request with the daemon to stream file data.
      fwrite($handler, "zINSTREAM\0");
      $bytes = filesize($file);
      if ($bytes > 0) {
        // Tell the daemon how many bytes of data we're sending.
        fwrite($handler, pack("N", $bytes));
        // Send the file data.
        stream_copy_to_stream($filehandler, $handler);
      }
      // Send a zero-length block to indicate that we're done sending file data.
      fwrite($handler, pack("N", 0));
      $response = fgets($handler);
      fclose($filehandler);
      fclose($handler);
      $response = trim($response);

      if ($debug) {
        watchdog('antivirus', 'ClamAV Daemon response for %file: %response', array('%file' => $file, '%response' => $response), WATCHDOG_NOTICE);
      }
    }
    else {
      watchdog('antivirus', 'Uploaded file %file could not be scanned: failed to open file handle.', array('%file' => $file), WATCHDOG_WARNING);
      return ANTIVIRUS_CLAMAVDAEMON_SCAN_UNCHECKED;
    }

    // clamd returns a string response in the format:
    // stream: OK
    // stream: <name of virus> FOUND
    // stream: <error string> ERROR
    if (preg_match('/^stream: OK$/', $response)) {
      // Log the message to watchdog, if verbose mode is used.
      if (in_array('-v', $flags)) {
        watchdog('antivirus', 'File %file scanned by ClamAV and found clean.', array('%file' => $file), WATCHDOG_INFO);
      }
      return ANTIVIRUS_CLAMAVDAEMON_SCAN_OK;
    }
    elseif (preg_match('/^stream: (.*) FOUND$/', $response, $matches)) {
      $virus_name = $matches[1];
      watchdog('antivirus', 'Virus detected in uploaded file %file.  Clamav-daemon reported the virus:<br />@virus_name', array('%file' => $file, '@virus_name' => $virus_name), WATCHDOG_CRITICAL);
      return ANTIVIRUS_CLAMAVDAEMON_SCAN_FOUND;
    }
    else {
      // try to extract the error message from the response.
      preg_match('/^stream: (.*) ERROR$/', $response, $matches);
      $error_string = $matches[1]; // the error message given by the daemon
      watchdog('antivirus', 'Uploaded file %file could not be scanned.  Clamav-daemon reported:<br />@error_string', array('%file' => $file, '@error_string' => $error_string), WATCHDOG_WARNING);
  
      return ANTIVIRUS_CLAMAVDAEMON_SCAN_UNCHECKED;
    }
  }

  /**
   * Implementation of AntivirusScanner::configure().
   */
  public function configure(&$form) {
    $settings = variable_get('antivirus_settings_clamavdaemon', array());

    // @todo, can we use the first two flags for the daemon?
    $form['scanner_flags']['#options']['--quiet'] = t('Quiet mode (only print error messages).');
    $form['scanner_flags']['#options']['-i'] = t('Only print infected files.');
    $form['scanner_flags']['#options']['-v'] = t('Be verbose.');

    $form['scanner_info']['daemon_host'] = array(
      '#title' => 'ClamAV Daemon Host',
      '#type' => 'textfield',
      '#default_value' => $settings['host'],
    );

    $form['scanner_info']['daemon_port'] = array(
      '#title' => 'ClamAV Daemon Port',
      '#type' => 'textfield',
      '#default_value' => $settings['port'],
    );
  }

  /**
   * Implementation of AntivirusScanner::save().
   */
  public function save($values) {
    variable_set('antivirus_settings_clamavdaemon', array(
      'host' => $values['daemon_host'],
      'port' => $values['daemon_port'],
    ));
  }

}
