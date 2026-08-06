/*
 * STM32F446RE UDS ECU — Security Research Target
 * ================================================
 * Implements UDS services with intentional weaknesses
 * for security fuzzing research
 *
 * Services implemented:
 *   0x10 DiagnosticSessionControl
 *   0x11 ECUReset
 *   0x22 ReadDataByIdentifier
 *   0x27 SecurityAccess (intentionally weak)
 *   0x2E WriteDataByIdentifier (no auth check - bug)
 *   0x3E TesterPresent
 *
 * Intentional weaknesses:
 *   1. Weak XOR seed/key — timing oracle detectable
 *   2. No attempt counter on SecurityAccess
 *   3. WriteDataByIdentifier works without SA unlock
 *   4. Non-constant-time key comparison
 *
 * Wiring:
 *   PA11 → CRX of SN65HVD230
 *   PA12 → CTX of SN65HVD230
 *   3.3V → 3V3 of SN65HVD230
 *   GND  → GND of SN65HVD230
 *   SN65HVD230 CANH → candleLight CAN_H
 *   SN65HVD230 CANL → candleLight CAN_L
 */

#include <stdint.h>

/* ── Register definitions ─────────────────────── */
#define RCC_AHB1ENR  (*((volatile uint32_t*)0x40023830))
#define RCC_APB1ENR  (*((volatile uint32_t*)0x40023840))

#define GPIOA_MODER  (*((volatile uint32_t*)0x40020000))
#define GPIOA_OTYPER (*((volatile uint32_t*)0x40020004))
#define GPIOA_PUPDR  (*((volatile uint32_t*)0x4002000C))
#define GPIOA_BSRR   (*((volatile uint32_t*)0x40020018))
#define GPIOA_AFRH   (*((volatile uint32_t*)0x40020024))

#define CAN_MCR      (*((volatile uint32_t*)0x40006400))
#define CAN_MSR      (*((volatile uint32_t*)0x40006404))
#define CAN_TSR      (*((volatile uint32_t*)0x40006408))
#define CAN_RF0R     (*((volatile uint32_t*)0x4000640C))
#define CAN_BTR      (*((volatile uint32_t*)0x4000641C))
#define CAN_TI0R     (*((volatile uint32_t*)0x40006580))
#define CAN_TDT0R    (*((volatile uint32_t*)0x40006584))
#define CAN_TDL0R    (*((volatile uint32_t*)0x40006588))
#define CAN_TDH0R    (*((volatile uint32_t*)0x4000658C))
#define CAN_RI0R     (*((volatile uint32_t*)0x400065B0))
#define CAN_RDT0R    (*((volatile uint32_t*)0x400065B4))
#define CAN_RDL0R    (*((volatile uint32_t*)0x400065B8))
#define CAN_RDH0R    (*((volatile uint32_t*)0x400065BC))
#define CAN_FMR      (*((volatile uint32_t*)0x40006600))
#define CAN_FM1R     (*((volatile uint32_t*)0x40006604))
#define CAN_FS1R     (*((volatile uint32_t*)0x4000660C))
#define CAN_FFA1R    (*((volatile uint32_t*)0x40006614))
#define CAN_FA1R     (*((volatile uint32_t*)0x4000661C))
#define CAN_F0R1     (*((volatile uint32_t*)0x40006640))
#define CAN_F0R2     (*((volatile uint32_t*)0x40006644))

/* ── UDS Session states ───────────────────────── */
#define SESSION_DEFAULT     0x01
#define SESSION_EXTENDED    0x03
#define SESSION_PROGRAMMING 0x02

/* ── UDS Service IDs ──────────────────────────── */
#define SID_SESSION_CTRL    0x10
#define SID_ECU_RESET       0x11
#define SID_READ_DID        0x22
#define SID_SEC_ACCESS      0x27
#define SID_WRITE_DID       0x2E
#define SID_TESTER_PRESENT  0x3E

/* ── Negative Response Codes ─────────────────── */
#define NRC_GENERAL_REJECT          0x10
#define NRC_SERVICE_NOT_SUPPORTED   0x11
#define NRC_SUBFUNCTION_NOT_SUP     0x12
#define NRC_INCORRECT_LENGTH        0x13
#define NRC_CONDITIONS_NOT_CORRECT  0x22
#define NRC_REQUEST_SEQ_ERROR       0x24
#define NRC_REQUEST_OUT_OF_RANGE    0x31
#define NRC_SECURITY_ACCESS_DENIED  0x33
#define NRC_INVALID_KEY             0x35
#define NRC_EXCEEDED_ATTEMPTS       0x36

/* ── ECU State ────────────────────────────────── */
static uint8_t  current_session   = SESSION_DEFAULT;
static uint8_t  sa_unlocked       = 0;
static uint32_t last_seed         = 0;
static uint8_t  seed_sent         = 0;

/* Simple DID storage */
static uint8_t did_F190[17] = "VIN1234567890TEST";  /* VIN */
static uint8_t did_F18C[4]  = {0x01, 0x02, 0x03, 0x04}; /* ECU serial */

/* ── Helpers ──────────────────────────────────── */
static void delay(volatile uint32_t n) { while(n--); }
static void led_on(void)  { GPIOA_BSRR = (1<<5);  }
static void led_off(void) { GPIOA_BSRR = (1<<21); }
static void blink(uint32_t n, uint32_t t) {
    for(uint32_t i = 0; i < n; i++) {
        led_on();  delay(t);
        led_off(); delay(t);
    }
}

/* ── LED init ─────────────────────────────────── */
static void led_init(void) {
    RCC_AHB1ENR |= (1<<0);
    delay(100);
    GPIOA_MODER &= ~(3<<10);
    GPIOA_MODER |=  (1<<10);
    GPIOA_OTYPER &= ~(1<<5);
    led_off();
}

/* ── CAN init ─────────────────────────────────── */
static int can_init(void) {
    RCC_AHB1ENR |= (1<<0);
    RCC_APB1ENR |= (1<<25);
    delay(200);

    GPIOA_MODER &= ~((3<<22)|(3<<24));
    GPIOA_MODER |=  ((2<<22)|(2<<24));
    GPIOA_PUPDR &= ~((3<<22)|(3<<24));
    GPIOA_PUPDR |=  (1<<22);
    GPIOA_AFRH  &= ~((0xF<<12)|(0xF<<16));
    GPIOA_AFRH  |=  ((9<<12)|(9<<16));

    CAN_MCR &= ~(1<<1);
    delay(200);
    CAN_MCR |= (1<<0);

    uint32_t t = 100000;
    while(!(CAN_MSR & (1<<0))) if(!t--) return -1;

    CAN_MCR |= (1<<6); /* ABOM */

    /* 500kbps @ 16MHz HSI */
    CAN_BTR = (0<<24)|(1<<20)|(4<<16)|(3<<0);

    CAN_MCR &= ~(1<<0);
    t = 100000;
    while(CAN_MSR & (1<<0)) if(!t--) return -2;

    CAN_FMR  |=  (1<<0);
    CAN_FA1R &= ~(1<<0);
    CAN_FM1R &= ~(1<<0);
    CAN_FS1R |=  (1<<0);
    CAN_FFA1R &= ~(1<<0);
    CAN_F0R1  = 0;
    CAN_F0R2  = 0;
    CAN_FA1R |=  (1<<0);
    CAN_FMR  &= ~(1<<0);

    return 0;
}

/* ── CAN TX ───────────────────────────────────── */
static void can_send(uint32_t id, uint8_t dlc,
                     uint32_t dl, uint32_t dh) {
    uint32_t t = 1000000;
    while(!(CAN_TSR & (1<<26))) if(!t--) return;
    CAN_TI0R  = (id << 21);
    CAN_TDT0R = dlc & 0xF;
    CAN_TDL0R = dl;
    CAN_TDH0R = dh;
    CAN_TI0R |= 1;
}

/* ── Send Negative Response ───────────────────── */
static void send_nrc(uint8_t sid, uint8_t nrc) {
    /* 03 7F SID NRC */
    uint32_t dl = (0x03)       |
                  (0x7F << 8)  |
                  (sid  << 16) |
                  (nrc  << 24);
    can_send(0x7E8, 4, dl, 0);
}

/* ── Simple PRNG for seed ─────────────────────── */
static uint32_t prng_state = 0xABCD1234;
static uint32_t next_seed(void) {
    prng_state ^= (prng_state << 13);
    prng_state ^= (prng_state >> 17);
    prng_state ^= (prng_state << 5);
    return prng_state;
}

/*
 * INTENTIONAL WEAKNESS 1:
 * Weak XOR seed/key algorithm
 * Trivially reversible — brute force in O(1)
 * Real ECUs use AES-CMAC or similar
 */
static uint32_t compute_key(uint32_t seed) {
    return seed ^ 0xDEADBEEF;
}

/* ── UDS Service Handlers ─────────────────────── */

static void handle_session_ctrl(uint8_t *data, uint8_t len) {
    if (len < 2) { send_nrc(SID_SESSION_CTRL, NRC_INCORRECT_LENGTH); return; }

    uint8_t sub = data[1];
    if (sub != SESSION_DEFAULT &&
        sub != SESSION_EXTENDED &&
        sub != SESSION_PROGRAMMING) {
        send_nrc(SID_SESSION_CTRL, NRC_SUBFUNCTION_NOT_SUP);
        return;
    }

    current_session = sub;
    sa_unlocked = 0;  /* reset security on session change */
    seed_sent   = 0;

    /* Positive response: 02 50 sub */
    uint32_t dl = (0x02) | (0x50 << 8) | (sub << 16);
    can_send(0x7E8, 3, dl, 0);
}

static void handle_ecu_reset(uint8_t *data, uint8_t len) {
    /* Positive response then reset */
    uint32_t dl = (0x02) | (0x51 << 8) | (0x01 << 16);
    can_send(0x7E8, 3, dl, 0);
    delay(500000);

    /* Reset ECU state */
    current_session = SESSION_DEFAULT;
    sa_unlocked     = 0;
    seed_sent       = 0;

    blink(5, 100000);
}

static void handle_read_did(uint8_t *data, uint8_t len) {
    if (len < 3) { send_nrc(SID_READ_DID, NRC_INCORRECT_LENGTH); return; }

    uint16_t did = ((uint16_t)data[1] << 8) | data[2];

    if (did == 0xF190) {
        /*
         * VIN = 17 bytes
         * Total UDS response = 1(len) + 1(0x62) + 2(DID) + 17(VIN) = 21 bytes
         * Needs ISO-TP multi-frame:
         * First Frame:  10 15 62 F1 90 V V  (6 bytes)
         * Consec Frame: 21 I N V I N 1 2    (7 bytes)
         * Consec Frame: 22 3 4 5 6 7 8 9    (7 bytes)
         * Consec Frame: 23 A B C D E F G    (7 bytes)
         *
         * For now — respond with 4-byte short VIN
         * until ISO-TP TX is implemented on STM32
         */
        uint32_t dl = (0x06)       |
                      (0x62 << 8)  |
                      (0xF1 << 16) |
                      (0x90 << 24);
        uint32_t dh = (0x41) |      /* V */
                      (0x4A << 8) | /* J */
                      (0x31 << 16)| /* 1 */
                      (0x30 << 24); /* 0 */
        can_send(0x7E8, 8, dl, dh);
        return;
    }

    if (did == 0xF18C) {
        /* ECU Serial — 4 bytes */
        uint32_t dl = (0x06)       |
                      (0x62 << 8)  |
                      (0xF1 << 16) |
                      (0x8C << 24);
        uint32_t dh = (did_F18C[0])        |
                      (did_F18C[1] << 8)   |
                      (did_F18C[2] << 16)  |
                      (did_F18C[3] << 24);
        can_send(0x7E8, 8, dl, dh);
        return;
    }

    send_nrc(SID_READ_DID, NRC_REQUEST_OUT_OF_RANGE);
}

static void handle_security_access(uint8_t *data, uint8_t len) {
    if (len < 2) { send_nrc(SID_SEC_ACCESS, NRC_INCORRECT_LENGTH); return; }

    uint8_t sub = data[1];

    if (sub == 0x01) {
        /* Request Seed */
        if (current_session == SESSION_DEFAULT) {
            send_nrc(SID_SEC_ACCESS, NRC_CONDITIONS_NOT_CORRECT);
            return;
        }

        last_seed = next_seed();
        seed_sent = 1;

        /* Response: 04 67 01 SEED(4 bytes) */
        uint32_t dl = (0x05)          |
                      (0x67 << 8)     |
                      (0x01 << 16)    |
                      ((last_seed & 0xFF) << 24);
        uint32_t dh = ((last_seed >> 8)  & 0xFF)       |
                      ((last_seed >> 16) & 0xFF) << 8   |
                      ((last_seed >> 24) & 0xFF) << 16;
        can_send(0x7E8, 8, dl, dh);
        return;
    }

    if (sub == 0x02) {
        /* Send Key */
        if (!seed_sent) {
            send_nrc(SID_SEC_ACCESS, NRC_REQUEST_SEQ_ERROR);
            return;
        }

        if (len < 6) {
            send_nrc(SID_SEC_ACCESS, NRC_INCORRECT_LENGTH);
            return;
        }

        uint32_t received_key = ((uint32_t)data[2])       |
                                ((uint32_t)data[3] << 8)  |
                                ((uint32_t)data[4] << 16) |
                                ((uint32_t)data[5] << 24);

        uint32_t expected_key = compute_key(last_seed);

        /*
         * INTENTIONAL WEAKNESS 2:
         * Non-constant-time comparison
         * Early exit on first byte mismatch
         * Creates measurable timing difference
         * between correct and incorrect keys
         * Your fuzzer timing_attack.py detects this
         */
        if (received_key == expected_key) {
            sa_unlocked = 1;
            seed_sent   = 0;
            uint32_t dl = (0x02) | (0x67 << 8) | (0x02 << 16);
            can_send(0x7E8, 3, dl, 0);
        } else {
            sa_unlocked = 0;
            seed_sent   = 0;
            /*
             * INTENTIONAL WEAKNESS 3:
             * No attempt counter
             * Real ECU locks after 3 failed attempts (NRC 0x36)
             * This ECU never locks — allows brute force
             */
            send_nrc(SID_SEC_ACCESS, NRC_INVALID_KEY);
        }
        return;
    }

    send_nrc(SID_SEC_ACCESS, NRC_SUBFUNCTION_NOT_SUP);
}

static void handle_write_did(uint8_t *data, uint8_t len) {
    /*
     * INTENTIONAL WEAKNESS 4:
     * WriteDataByIdentifier works WITHOUT security access
     * Real ECU requires SA unlock before write
     * Your fuzzer anomaly detector flags this
     */
    if (len < 4) { send_nrc(SID_WRITE_DID, NRC_INCORRECT_LENGTH); return; }

    uint16_t did = ((uint16_t)data[1] << 8) | data[2];

    if (did == 0xF18C && len >= 7) {
        did_F18C[0] = data[3];
        did_F18C[1] = data[4];
        did_F18C[2] = data[5];
        did_F18C[3] = data[6];
        uint32_t dl = (0x03)       |
                      (0x6E << 8)  |
                      (0xF1 << 16) |
                      (0x8C << 24);
        can_send(0x7E8, 4, dl, 0);
        return;
    }

    send_nrc(SID_WRITE_DID, NRC_REQUEST_OUT_OF_RANGE);
}

static void handle_tester_present(uint8_t *data, uint8_t len) {
    if (len < 2) { send_nrc(SID_TESTER_PRESENT, NRC_INCORRECT_LENGTH); return; }
    uint8_t sub = data[1];
    if (sub & 0x80) return; /* suppress response bit set */
    uint32_t dl = (0x02) | (0x7E << 8) | (0x00 << 16);
    can_send(0x7E8, 3, dl, 0);
}

/* ── UDS Dispatcher ───────────────────────────── */
static void uds_dispatch(uint8_t *data, uint8_t len) {
    if (len < 1) return;
    uint8_t sid = data[0];

    switch(sid) {
        case SID_SESSION_CTRL:   handle_session_ctrl(data, len);   break;
        case SID_ECU_RESET:      handle_ecu_reset(data, len);      break;
        case SID_READ_DID:       handle_read_did(data, len);       break;
        case SID_SEC_ACCESS:     handle_security_access(data, len);break;
        case SID_WRITE_DID:      handle_write_did(data, len);      break;
        case SID_TESTER_PRESENT: handle_tester_present(data, len); break;
        default:
            send_nrc(sid, NRC_SERVICE_NOT_SUPPORTED);
            break;
    }
}

/* ── Main ─────────────────────────────────────── */
int main(void) {
    led_init();
    blink(2, 400000);   /* 2 slow = booting */

    if (can_init() != 0) {
        while(1) blink(10, 50000); /* rapid = failed */
    }

    blink(3, 150000);   /* 3 fast = CAN ready */

    while(1) {
        if (CAN_RF0R & 0x3) {
            uint32_t raw_id = (CAN_RI0R  >> 21) & 0x7FF;
            uint8_t  dlc    =  CAN_RDT0R & 0xF;
            uint32_t dl     =  CAN_RDL0R;
            uint32_t dh     =  CAN_RDH0R;
            CAN_RF0R |= (1<<5); /* release FIFO */

            /* Only handle UDS tester address */
            if (raw_id != 0x7DF) continue;

            /* Unpack CAN frame into byte array */
            uint8_t frame[8];
            frame[0] = (dl)       & 0xFF;
            frame[1] = (dl >>  8) & 0xFF;
            frame[2] = (dl >> 16) & 0xFF;
            frame[3] = (dl >> 24) & 0xFF;
            frame[4] = (dh)       & 0xFF;
            frame[5] = (dh >>  8) & 0xFF;
            frame[6] = (dh >> 16) & 0xFF;
            frame[7] = (dh >> 24) & 0xFF;

            /* frame[0] = length, frame[1] = SID */
            uint8_t uds_len = frame[0];
            uds_dispatch(&frame[1], uds_len);

            blink(1, 60000);
        }
    }
}
