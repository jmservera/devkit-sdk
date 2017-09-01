#include "DiceInit.h"

static int status;

void setup() {
  // put your setup code here, to run once:
  delay(1000);
  Serial.println("Start to run Dice+RIoT application.\r\n");
  delay(100);
  status = StartDiceInit();
  Serial.println(status);
  if (status == 0){
    Serial.println("Finish Dice+RIoT application successfully.\r\n");
  }
}

void loop() {
  // put your main code here, to run repeatedly:

}
