<?php
/**
 * F-TICKS logger Authentication Processing filter
 *
 * @author Tamas Frank <sitya@niif.hu>
 * @author Gyula Szabó <gyufi@sztaki.hu>
 * @package simpleSAMLphp
 * @version $Id$
 */
namespace SimpleSAML\Module\ftickslogger\Auth\Process;
 
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;

class ftickslogger extends ProcessingFilter
{

/**
	 * The attribute to log
	 */
	private $attribute = NULL;
	private $secretsalt = NULL;

	private $typeTag = 'FTICKS/eduid.hu/1.0/';

	/**
	 * Initialize this filter.
	 *
	 * @param array $config  Configuration information about this filter.
	 * @param mixed $reserved  For future use.
	 */
	public function __construct($config, $reserved) {
		parent::__construct($config, $reserved);

		assert('is_array($config)');

		if (array_key_exists('attributename', $config)) {
			$this->attribute = $config['attributename'];
			if (!is_string($this->attribute)) {
				throw new Exception('Invalid attribute name given to fticklogger filter.');
			}
		}

		if (array_key_exists('secretsalt', $config)) {
			$this->secretsalt = $config['secretsalt'];
			if (!is_string($this->secretsalt)) {
				throw new Exception('Invalid secretsalt given to fticklogger filter.');
			}
		}

	}


	/**
	 * Log line.
	 *
	 * @param array &$state  The current state.
	 */
	public function process(&$state) {
		assert('is_array($state)');
		assert('array_key_exists("Attributes", $state)');

		$TS = time();
		$AP = 'NA';
		$RP = 'NA';
		$PN = 'NA';
		$AM = 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password';

		if (array_key_exists($this->attribute, $state['Attributes'])) {
			$PN = hash('sha256', $state['Attributes'][$this->attribute][0] . $this->secretsalt);
		}
		if (array_key_exists('Source', $state)) {
				$AP = $state['Source']['entityid'];
		}

		if (array_key_exists('Destination', $state)) {
			$RP = $state['Destination']['entityid'];
		}

		Logger::stats($this->typeTag . '#TS=' . $TS . '#AP=' . $AP . '#RP=' . $RP . '#PN=' . $PN . '#AM=' . $AM . '#');
	}

}
