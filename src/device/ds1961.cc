#include "ds1961.h"
#include "lib/sha33.h"
#include "lib/crc.h"
#include "../master/bus/bus.h"
#include "../shared/v8_helper.h"
#include <stdint.h>
#include <string.h>
#include <time.h>

using namespace v8;

// commands used in the DS1961
#define CMD_WRITE_SCRATCHPAD     0x0F
#define CMD_COMPUTE_NEXT_SECRET  0x33
#define CMD_COPY_SCRATCHPAD      0x55
#define CMD_LOAD_FIRST_SECRET    0x5A
#define CMD_REFRESH_SCRATCHPAD   0xA3
#define CMD_READ_AUTH_PAGE       0xA5
#define CMD_READ_SCRATCHPAD      0xAA
#define CMD_READ_MEMORY          0xF0

// memory ranges
#define MEM_DATA_PAGE_0          0x00
#define MEM_DATA_PAGE_1          0x20
#define MEM_DATA_PAGE_2          0x40
#define MEM_DATA_PAGE_3          0x60
#define MEM_SECRET               0x80
#define MEM_IDENTITY             0x90

#ifdef DS1961_DEBUG
#  define DPRINT(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#  define DPRINT(fmt, ...)
#endif

const struct timespec T_CSHA = { .tv_sec = 0, .tv_nsec =  1500000 }; //  1.5 ms
const struct timespec T_PROG = { .tv_sec = 0, .tv_nsec = 10000000 }; // 10.0 ms

Ds1961::Ds1961 (Bus* bus, uint64_t intDeviceId, std::string* strDeviceId)
    : Device (bus, intDeviceId, strDeviceId)
{
    // 3-byte challenge for authentication; default: random
    REGISTER_UPDATER(Ds1961::UpdateAuthChallenge, "auth_challenge", "");
    // address for reading authenticated data; default: 0x0
    REGISTER_UPDATER(Ds1961::UpdateAuthAddress, "auth_address", "");
    // secret for authenticated data
    REGISTER_UPDATER(Ds1961::UpdateAuthSecret, "auth_secret", "");

    // secret to write
    REGISTER_UPDATER(Ds1961::UpdateSecret, "secret", "");
    REGISTER_UPDATER(Ds1961::GenerateSecret, "generate_secret", "");

    // address for writing data; default: 0x0
    REGISTER_UPDATER(Ds1961::UpdateDataAddress, "data_address", "");
    // MAC for writing data
    REGISTER_UPDATER(Ds1961::UpdateDataMAC, "data_mac", "");
    // data to be written
    REGISTER_UPDATER(Ds1961::UpdateData, "data", "");
}


bool
Ds1961::UpdateAuthAddress (const char *value)
{
    param_auth_addr = atoi(value);
    return true;
}


bool
Ds1961::UpdateAuthChallenge (const char *value)
{
    memcpy (param_auth_challenge, value, 3);
    auth_challenge_set = true;
    return true;
}


bool
Ds1961::UpdateAuthSecret (const char *value)
{
    if (sizeof(param_auth_secret) != strnlen(value, sizeof(param_auth_secret) + 1))
        return false;

    memcpy (param_auth_secret, value, sizeof(param_auth_secret));
    auth_secret_set = true;
    return true;
 }


bool
Ds1961::UpdateSecret (const char *value)
{
    if (sizeof(param_auth_secret) != strnlen(value, sizeof(param_auth_secret) + 1))
        return false;

    return 0 == WriteSecret16((const uint8_t *) value);
}


/**
 *  Generate 8-byte secret and write it to the device.
 *
 *  The secret is stored in a 16 * 7-bit representation that
 *  is returned in
 */
bool
Ds1961::GenerateSecret (const char *value)
{
    srand(time(NULL));
    for (uint8_t i = 0; i < sizeof(gen_secret); i++)
        gen_secret[i] = (rand() % (0x7f - 1)) + 1;

    return 0 == WriteSecret16(gen_secret);
}


bool
Ds1961::UpdateDataAddress (const char *value)
{
    param_data_addr = atoi(value);
    return true;
}


bool
Ds1961::UpdateDataMAC (const char *value)
{
    // FIXME: utf8 fail
    if (sizeof(param_data_mac) != strnlen(value, sizeof(param_data_mac) + 1))
        return false;

    memcpy (param_data_mac, value, sizeof(param_data_mac));
    return true;
}


bool
Ds1961::UpdateData (const char *value)
{
    return 0 == WriteData(param_data_addr, (const uint8_t *) value, param_data_mac);
}


/**
 * Called upon reading values from this object.
 */
void
Ds1961::BuildValueData (Handle<Object> target)
{
    V8Helper::AddPairToV8Object(target, "generated_secret",
                                "%.*s", sizeof(gen_secret), gen_secret);

    if (!auth_secret_set)
        return;

    if (!auth_challenge_set)
    {   // no challenge set, generate one
        DPRINT("# generating challenge\n");
        srand(time(NULL));
        for (uint8_t i = 0; i < 3; i++)
            param_auth_challenge[i] = rand();
    }

    uint8_t
        bytes[32], ///< bytes read
        rmac[20],  ///< MAC calculated by device
        lmac[20];  ///< locally calculated MAC
    int ret = ReadAuthWithChallenge(param_auth_addr, param_auth_challenge,
                                    bytes, rmac);
    if (0 != ret)
    {
        V8Helper::AddPairToV8Object(target, "authenticated",
                                    "%s #%d", "ERROR",  -1 * ret);
        return;
    }

    DPRINT("# auth_addr: 0x%04x\n", param_auth_addr);
    DPRINT("# auth_challenge: %.*s\n", sizeof(param_auth_challenge), param_auth_challenge);
    DPRINT("# auth_secret:  %.*s\n", sizeof(param_auth_secret), param_auth_secret);

    uint8_t secret[8];
    Secret16to8(param_auth_secret, secret);

    DPRINT("# auth_secret8: %.*s\n", sizeof(secret), secret);
    CalcMacReadAuthPage(lmac, param_auth_addr, bytes,
                        secret, param_auth_challenge);

    DPRINT("# rmac: ");
    for (uint8_t i=0; i<sizeof(rmac); i++)
        DPRINT("%02x ", rmac[i]);

    DPRINT("\n# lmac: ");
    for (uint8_t i=0; i<sizeof(lmac); i++)
        DPRINT("%02x ", lmac[i]);
    DPRINT("\n");

    bool authenticated = (0 == memcmp(lmac, rmac, sizeof(rmac)));

    V8Helper::AddPairToV8Object(target, "authenticated",
                                "%s", authenticated ? "YES" : "NO");
    V8Helper::AddPairToV8Object(target, "auth_data",
                                "%.*s", sizeof(bytes), bytes);
    V8Helper::AddPairToV8Object(target, "auth_mac",
                                "%.*s", sizeof(rmac), rmac);
}


// private

/*** HIGH-LEVEL OPERATIONS ***/


int
Ds1961::ReadAuthWithChallenge (uint16_t addr, const uint8_t challenge[3],
                               uint8_t bytes[32], uint8_t mac[20])
{
    uint8_t scratchpad[8];

    // write the challenge on the scratchpad
    memset(scratchpad, 0, sizeof(scratchpad));
    memcpy(scratchpad + 4, challenge, 3);

    if (!WriteScratchPad(addr, scratchpad))
        return -2;

    // perform the authenticated read
    return
        ReadAuthPage(addr, bytes, mac)
        ? 0 : -1;
}


int
Ds1961::WriteSecret (const uint8_t secret[8])
{
    uint16_t addr;
    uint8_t es;
    uint8_t data[8];

    // write secret to scratch pad
    if (!WriteScratchPad(MEM_SECRET, secret)) {
        DPRINT("# FAIL: WriteScratchPad\n");
        return -3;
    }

    // read scratchpad for auth code
    if (!ReadScratchPad(&addr, &es, data)) {
        DPRINT("# FAIL: ReadScratchPad\n");
        return -2;
    }

    if (!LoadFirstSecret(addr, es))
    {
        DPRINT("# FAIL: LoadFirstSecret\n");
        return -1;
    }

    return 0;
}


int
Ds1961::WriteSecret16 (const uint8_t secret[16])
{
    uint8_t secret8[8];
    Secret16to8(secret, secret8);
    return WriteSecret(secret8);
}


/*
 * Write 8 bytes of data to specified address
 */
int
Ds1961::WriteData (uint16_t addr, const uint8_t data[8], const uint8_t mac[20])
{
    uint8_t spad[8];
    uint16_t ad;
    uint8_t es;

    // write data into scratchpad
    if (!WriteScratchPad(addr, data)) {
        return -5;
    }

    // read scratch pad for auth code
    if (!ReadScratchPad(&ad, &es, spad)) {
        return -4;
    }

    // copy scratchpad to EEPROM
    if (!CopyScratchPad(ad, es, mac)) {
        return -3;
    }

    // refresh scratchpad
    if (!RefreshScratchPad(addr, data)) {
        return -2;
    }

    // re-write with load first secret
    if (!LoadFirstSecret(addr, es)) {
        return -1;
    }

    return 0;
}


/*** DEVICE COMMANDS ***/


bool
Ds1961::WriteScratchPad (uint16_t addr, const uint8_t bytes[8])
{
    DPRINT(">> WriteScratchPad(%x, '%.*s')\n", addr, 8, bytes);
    uint8_t len = 0;

    // perform write scratchpad command
    data[0] = CMD_WRITE_SCRATCHPAD;
    Command(data[0]);
    len++;

    data[len++] = (addr >> 0) & 0xFF;    // 2 byte target address
    data[len++] = (addr >> 8) & 0xFF;    // 2 byte target address
    memcpy(data + len, bytes, 8);
    len += 8;

    for (uint8_t i = 1; i < len; i++)
        WriteByte(data[i]);

    // check CRC
    ReadBytes(len, 2);
    return InvCrc16DataValidate(len, len, len + 1);
}


bool
Ds1961::RefreshScratchPad (uint16_t addr, const uint8_t bytes[8])
{
    uint8_t len = 0;

    // perform refresh scratchpad command
    data[0] = CMD_REFRESH_SCRATCHPAD;
    Command(data[0]);
    len++;

    data[len++] = (addr >> 0) & 0xFF;    // 2 byte target address
    data[len++] = (addr >> 8) & 0xFF;    // 2 byte target address
    memcpy(data + len, bytes, 8);
    len += 8;

    for (uint8_t i = 1; i < len; i++)
        WriteByte(data[i]);

    // check CRC
    ReadBytes(len, 2);
    return InvCrc16DataValidate(len, len, len + 1);
}


bool
Ds1961::ReadScratchPad (uint16_t *addr, uint8_t *es, uint8_t bytes[8])
{
    DPRINT(">> ReadScratchPad()\n");
    uint8_t len = 0;

    // send read scratchpad command
    data[0] = CMD_READ_SCRATCHPAD;
    Command(data[0]);
    len++;

    // get TA0/1 and ES
    ReadBytes(len, 3);
    len += 3;
    *addr = (data[2] << 8) | data[1];
    *es = data[3];

    // get data
    ReadBytes(len, 8);
    memcpy(bytes, data + len, 8);
    len += 8;

    // check CRC
    ReadBytes(len, 2);
    return InvCrc16DataValidate(len, len, len + 1);
}


bool
Ds1961::CopyScratchPad (uint16_t addr, uint8_t es, const uint8_t mac[20])
{
    uint8_t len = 0;

    // send copy scratchpad command + arguments
    data[0] = CMD_COPY_SCRATCHPAD;
    Command(data[0]);
    len++;

    data[len++] = (addr >> 0) & 0xFF;    // 2 byte target address
    data[len++] = (addr >> 8) & 0xFF;    // 2 byte target address
    data[len++] = es;                    // es

    for (uint8_t i = 1; i < len; i++)
        WriteByte(data[i]);

    // keep powered and wait while MAC is calculated
    nanosleep(&T_CSHA, NULL);

    // send MAC
    for (uint8_t i = 0; i < 20; i++)
        WriteByte(mac[i]);

    nanosleep(&T_PROG, NULL);

    // check final status byte
    return (ReadByte() == 0xAA);
}


bool
Ds1961::ReadAuthPage (uint16_t addr, uint8_t bytes[32], uint8_t mac[20])
{
    uint8_t len = 0;

    // send command
    data[0] = CMD_READ_AUTH_PAGE;
    Command(data[0]);
    len++;

    data[len++] = (addr >> 0) & 0xFF;
    data[len++] = (addr >> 8) & 0xFF;

    for (uint8_t i = 1; i < len; i++)
        WriteByte(data[i]);

    // read data part + 0xFF
    ReadBytes(len, 33);
    len += 33;
    if (data[35] != 0xFF)
        return false;

    // check CRC
    ReadBytes(len, 2);
    if (!InvCrc16DataValidate(len, len, len + 1))
        return false;

    memcpy(bytes, data + 3, 32);

    // read MAC part
    nanosleep(&T_CSHA, NULL);
    len = 0;
    ReadBytes(len, 20);
    len += 20;
    memcpy(mac, data, len);

    // check CRC
    ReadBytes(len, 2);
    if (!InvCrc16DataValidate(len, len, len + 1))
        return false;

    // check final status byte
    uint8_t status = ReadByte();
    return (0xAA == status);
}


bool
Ds1961::LoadFirstSecret (uint16_t addr, uint8_t es)
{
    DPRINT(">> LoadFirstSecret(%x, %x)\n", addr, es);
    // send command
    Command(CMD_LOAD_FIRST_SECRET);

    WriteByte((addr >> 0) & 0xFF);    // 2 byte target address
    WriteByte((addr >> 8) & 0xFF);    // 2 byte target address

    // write auth code
    WriteByte(es);

    // keep powered and wait while secret is written
    nanosleep(&T_PROG, NULL);

    uint8_t status = ReadByte();
    DPRINT("<< LoadFirstSecret: 0x%x\n", status);
    return (0xAA == status);
}


bool
Ds1961::ReadMemory (int addr, int len, uint8_t bytes[])
{
    // send command
    Command(CMD_READ_MEMORY);

    WriteByte((addr >> 0) & 0xFF);    // 2 byte target address
    WriteByte((addr >> 8) & 0xFF);    // 2 byte target address

    // read data
    ReadBytes(len);
    memcpy(bytes, data, len);

    return true;
}


/*** Helper functions ***/


/**
 * Calculate MAC for the Read Authenticated Page operation.
 *
 * @param mac  Resulting MAC is written here.
 * @param addr Address of data.
 * @param pp   Data.
 * @param ss   Secret.
 * @param ch   Challenge.
 *
 */
void
Ds1961::CalcMacReadAuthPage (uint8_t mac[20], uint16_t addr, uint8_t pp[32],
                             uint8_t ss[8], uint8_t ch[3])
{
    uint32_t in[16];
    uint32_t hash[16];
    uint8_t id[7];
    uint64_t intid = GetIntId();
    int i;

    for (i = 0; i < 7; i++)
        id[i] = (intid & (0xFFLL << i * 8)) >> i * 8;

    in[0] = (ss[0] << 24) | (ss[1] << 16) | (ss[2] << 8) | ss[3];
    for (i = 0; i < 32; i += 4)
        in[i/4 + 1] = (pp[i] << 24) | (pp[i + 1] << 16) | (pp[i + 2] << 8) | pp[i + 3];

    in[9] = 0xFFFFFFFF;
    uint8_t mp = (0b1000 << 3) | ((addr >> 5) & 0b111);
    in[10] = (mp << 24) | (id[0] << 16) | (id[1] << 8) | id[2];
    in[11] = (id[3] << 24) | (id[4] << 16) | (id[5] << 8) | id[6];
    in[12] = (ss[4] << 24) | (ss[5] << 16) | (ss[6] << 8) | ss[7];
    in[13] = (ch[0] << 24) | (ch[1] << 16) | (ch[2] << 8) | 0x80;
    in[14] = 0;
    in[15] = 0x1B8;

    Sha33::ComputeSHAVM(in, hash);
    Sha33::HashToMAC(hash, mac);
}


bool
Ds1961::InvCrc16DataValidate (uint8_t buildByteCount,
                              uint8_t idxByte1Crc16Expected,
                              uint8_t idxByte2Crc16Expected){
    return Crc::Validate16Bit(data, buildByteCount,
                              ~data[idxByte1Crc16Expected],
                              ~data[idxByte2Crc16Expected]);
}


/**
 * Convert 16 * 7-bit representation of the secret to 8 * 8 bits.
 */
void
Ds1961::Secret16to8 (const uint8_t in[16], uint8_t out[8])
{
    for (uint8_t i = 0; i < 8; i++)
        out[i] = (in[2 * i + 1] << 8) | (in[2 * i]);
}
