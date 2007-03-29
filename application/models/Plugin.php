<?php
require_once 'Metafield.php';
require_once 'PluginTable.php';
/**
 * Used for plugin storage in the database
 *
 * @package default
 * 
 **/
class Plugin extends Doctrine_Record
{
	public function setUp() {
		$this->ownsMany("Metafield as Metafields", "Metafield.plugin_id");
	}
	
 	public function setTableDefinition() {
		$this->setTableName("plugins");
		$this->hasColumn("name", "string", 255, "unique|notblank");
		$this->hasColumn("description", "string");
		$this->hasColumn("author", "string");
		$this->hasColumn("config", "array");
		$this->hasColumn("active", "boolean");
	}
} // END class Location extends Kea_Record


?>