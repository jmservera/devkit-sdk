#include <ArduinoUnit.h>
#define LOOP_DELAY          500

unsigned long T_time;

void setup() {
  Serial.println(__FILE__);

  pinMode(LED_BUILTIN, OUTPUT);
}

void loop() {
  Test::run();
}

test(check_timedelay)
{
    digitalWrite(LED_BUILTIN, HIGH);
    delay(LOOP_DELAY); 
    digitalWrite(LED_BUILTIN, LOW);
    delay(LOOP_DELAY);

    digitalWrite(LED_BUILTIN, HIGH);
    delayMicroseconds(LOOP_DELAY);
    digitalWrite(LED_BUILTIN, LOW);
    delayMicroseconds(LOOP_DELAY);
}

test(check_timemicros_timemillis)
{
    Serial.print("Time:");
    T_time = micros();
    
    //print time
    Serial.println(T_time);
    delay(LOOP_DELAY); 

    T_time = millis();
  
    //print time
    Serial.println(T_time);
    delay(LOOP_DELAY);
}
