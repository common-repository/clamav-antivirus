<?php
/**
 * Container to store responses from virus scanner
 *
 * Since the ClamAVDaemon scanner was originally made for Drupal,
 * we provide some methods here to be compatible.
 *
 * @author Stephan van de Haar
 */
class AntivirusScanner {
	/** @var string */
    protected $name;
    /** @var array */
    static private $log = array();

    /**
     * Compatibility
     */
    protected function getFlags() {
        return array();
    }
	/**
	 * Adds a message from watchdog
	 *
	 * @param string $msg
	 */
    static public function addMessage($msg) {
        self::$log[] = $msg;
    }

    /**
     * Gets the last message
     *
     * @return mixed
     */
    public function getLastMessage() {
        return end(self::$log);
    }


}
/**
 * Compatibility
 */
function variable_get() {}
/**
 * Compatibility with Drupal watchdog
 *
 * @param unknown_type $cat
 * @param unknown_type $msg
 * @param unknown_type $args
 */
function watchdog($cat, $msg, $args) {
    AntivirusScanner::addMessage(str_replace(array_keys($args), array_values($args), $msg));
}