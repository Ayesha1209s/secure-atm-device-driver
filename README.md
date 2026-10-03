# Secure ATM PIN Authenticator Device Driver (Linux LKM Capstone Project)

![License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)
![Language](https://img.shields.io/badge/Kernel-C%20(LKM)-red.svg)
![User Space](https://img.shields.io/badge/User%20Space-C%2B%2B17%20OOP-green.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20Kernel%20%2F%20WSL2-orange.svg)

---

## 1. Executive Summary & Architecture

The **Secure ATM PIN Authenticator Device Driver** is a production-grade Linux Loadable Kernel Module (LKM) and companion C++17 user-space banking interface. It implements a privileged **Hardware Security Module (HSM)** simulator inside the Linux kernel to protect financial PIN validation against user-space memory inspection, reverse engineering, and timing side-channel attacks.

### Real-World Financial Security & Banking Features:
1. **Persistent Customer Database (`atm_accounts.dat`):** Pre-registered customers (e.g., Ayesha, Alice) are saved to disk. When you walk up to the ATM, you select your registered card in **1 second**—no need to register every time!
2. **Dynamic Account Balance Persistence:** Cash withdrawals and deposits immediately update the customer database file.
3. **Ring 0 Privileged Isolation:** PIN validation executes within the Linux kernel, preventing user-space memory dumping.
4. **Timing Side-Channel Resistance:** Uses `crypto_memneq()` for strict constant-time comparison.
5. **24-Hour Security Hold (Cooldown Policy):** 3 consecutive failed attempts place the card on a temporary security hold (configured to 30 seconds for live demo evaluations). Once expired, the driver resets automatically.
6. **Bank Officer In-Branch PUK Override:** Emulates branch customer service where an authorized teller enters a Master PUK (`778899`) to immediately clear a security hold.
7. **Memory Sanitization:** Explicit buffer scrubbing (`memzero_explicit`) prevents residual credentials from lingering in RAM.

---

## 2. Interactive Menu & Workflow

```text
================================================================
      SECURE ATM TERMINAL - KERNEL HSM AUTHENTICATOR v1.3       
================================================================
 [HARDWARE]: VIRTUAL KERNEL HSM (WSL2 Active)
 [SECURITY]: OPERATIONAL (Nominal)
 [CARD]:     NO CARD INSERTED
 [SESSION]:  UNAUTHENTICATED
----------------------------------------------------------------
MAIN MENU:
  1. Insert Debit Card (Select Registered or Add New)
  2. Enter PIN & Authenticate (via Kernel HSM)
  3. Inquire Account Balance
  4. Cash Withdrawal
  5. Deposit Funds
  6. Inspect Hardware & Kernel Diagnostics
  7. Eject Card / Terminate Session
  8. Bank Officer Security Override (Enter Master PUK)
  9. Exit Application
----------------------------------------------------------------
```

### Registered Cards On File (Instant Insertion):
When you press `1`:
```text
REGISTERED CARDS ON FILE (Pick to Insert Instantly):
  1. Ayesha             [Card: 4532-8801-9923-1044] [Balance: $15,000.00] (PIN: 2580)
  2. Alice V. Mercer    [Card: 5120-1122-3344-5566] [Balance: $8,500.50]  (PIN: 1234)
  3. John Doe           [Card: 4000-1234-5678-9010] [Balance: $3,200.00]  (PIN: 9999)
  4. + Issue & Register a Brand New Card
Select card to insert [1-4]:
```

---

## 3. How to Build & Run

### Step 1: Compile Application
```bash
make app
```

### Step 2: Launch ATM Interface
```bash
./atm_app
```

---

## 4. Security Evaluation Scenarios

- **Instant Card Insertion:** Type `1`, then choose `1` (Ayesha). The card is inserted instantly!
- **Authenticate:** Type `2` and enter PIN `2580`. Access granted!
- **Withdraw Money:** Type `4` and withdraw `$500`. Your balance updates from `$15,000` to `$14,500` and is permanently saved in `atm_accounts.dat`.
- **Security Lockout:** Eject (`7`), re-insert (`1`), and enter 3 incorrect PINs (`0000`, `1111`, `2222`). The 24-hour hold triggers!
- **Bank Override:** Choose `8` and enter PUK `778899` to unlock immediately.
