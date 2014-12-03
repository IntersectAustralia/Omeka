<?php
class Custom_Validate_RequiredIfCheckedValidator extends Zend_Validate_Abstract {

    const REQUIRED = 'required';

    protected $element;

    protected $_messageTemplates = array(
        self::REQUIRED => "Field is required",
    );

    public function __construct( Zend_Form_Element_Checkbox $element )
    {
        $this->element = $element;
    }

    public function isValid( $value )
    {
        $this->_setValue( $value );

        if( $this->element->isChecked() && $value === '' ) {
            $this->_error( self::REQUIRED );
            return false;
        }

        return true;
    }
}