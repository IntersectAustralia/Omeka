<?php
/**
 * @copyright Center for History and New Media, 2010
 * @license http://www.gnu.org/licenses/gpl-3.0.txt
 * @package Omeka
 */

/**
 * Test class for item_has_type.
 *
 * @package Omeka
 * @copyright Center for History and New Media, 2010
 */
class Omeka_Helper_ItemHasTypeTest extends Omeka_Test_AppTestCase
{
    /**
     * Tests that item_has_type behaves the same when an item is
     * set on the view and when it is directly passed.
     */
    public function testItemHasSpecificTypeWithNoItemOnView()
    {
        $typeId = 1;
        $type = get_db()->getTable('ItemType')->find(1);
        $typeName = $type->name;

        $item = new Item;
        $item->item_type_id = $typeId;

        $this->assertTrue(item_has_type($typeName, $item));
        $this->assertFalse(item_has_type('Not ' . $typeName, $item));

        __v()->item = $item;

        $this->assertTrue(item_has_type($typeName));
        $this->assertFalse(item_has_type('Not ' . $typeName, $item));
    }
}