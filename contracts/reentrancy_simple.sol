 pragma solidity ^0.8.0;
 contract Reentrance {
     mapping (address => uint) userBalance;
     function getBalance(address u) public view returns(uint){
         return userBalance[u];
     }
     function addToBalance() payable{
         userBalance[msg.sender] += msg.value;
     }
     function withdrawBalance(){
         if( ! (msg.sender.call.value(userBalance[msg.sender])() ) ){
             revert();
         }
         userBalance[msg.sender] = 0;
     }
 }