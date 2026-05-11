pragma solidity ^0.4.0;

contract SimpleSuicide {
  // <yes> <report> ACCESS_CONTROL
  function sudicideAnyone() {
    selfdestruct(msg.sender);
  }

}