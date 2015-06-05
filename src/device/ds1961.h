#ifndef DS1961_H
#define DS1961_H

#include "device.h"
#include "stdint.h"
#include "../master/bus/bus.h"

using namespace v8;


class Ds1961 : public Device {

 public:
	Ds1961(Bus*, uint64_t, std::string*);

        bool
        UpdateAuthAddress (const char *value);

        bool
        UpdateAuthChallenge (const char *value);

        bool
        UpdateAuthSecret (const char *value);

        bool
        UpdateSecret (const char *value);

        bool
        GenerateSecret (const char *value);

        bool
        UpdateDataAddress (const char *value);

        bool
        UpdateDataMAC (const char *value);

        bool
        UpdateData (const char *value);

        void
        BuildValueData (Handle<Object> target);
        
 private:
        int
        ReadAuthWithChallenge (uint16_t addr, const uint8_t challenge[3],
                               uint8_t data[32], uint8_t mac[20]);

        int
        WriteSecret (const uint8_t secret[8]);

        int
        WriteSecret16 (const uint8_t secret[16]);

        int
        WriteData (uint16_t addr, const uint8_t data[8], const uint8_t mac[20]);

        bool
        WriteScratchPad (uint16_t addr, const uint8_t bytes[8]);

        bool
        RefreshScratchPad (uint16_t addr, const uint8_t bytes[8]);

        bool
        ReadScratchPad (uint16_t *addr, uint8_t *es, uint8_t bytes[8]);

        bool
        CopyScratchPad (uint16_t addr, uint8_t es, const uint8_t mac[20]);

        bool
        ReadAuthPage (uint16_t addr, uint8_t bytes[32], uint8_t mac[20]);

        bool
        LoadFirstSecret (uint16_t addr, uint8_t es);

        bool
        ReadMemory (int addr, int len, uint8_t bytes[]);

        void
        CalcMacReadAuthPage (uint8_t mac[20], uint16_t addr, uint8_t pp[32],
                             uint8_t ss[8], uint8_t ch[3]);

        bool
        InvCrc16DataValidate (uint8_t buildByteCount,
                              uint8_t idxByte1Crc16Expected,
                              uint8_t idxByte2Crc16Expected);

        void
        Secret16to8 (const uint8_t in[16], uint8_t out[8]);

        bool auth_secret_set = false, auth_challenge_set = false;
        uint8_t
            gen_secret[16] = {0},
            param_auth_secret[16] = {0},
            param_auth_challenge[3] = {0},
            param_data_mac[20] = {0};
        uint16_t param_auth_addr = 0, param_data_addr = 0;
};

#endif
