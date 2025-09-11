# @zk-game-dao/currency: Multi-Currency Authentication & Ledger Interface for Internet Computer

The currency library is a comprehensive solution for handling authentication and ledger interactions on the Internet Computer Protocol (ICP), providing seamless integration with various token types, including native IC tokens and chain-fusion (ck) tokens.

## 🌟 Features

- **Multi-Currency Support**: Interact with ICP, CKBTC, CKETH, CKUSDC, CKUSDT, and other ICRC-1 tokens
- **Authentication System**: Multiple auth methods including Internet Identity, Web3Auth, and Sign-In with Bitcoin (SIWB)
- **Chain Fusion Integration**: Convert native tokens (BTC, ETH) to their canister (ck) versions
- **Semi-Custodial Wallets**: Manage user funds with secure, semi-custodial wallet solutions
- **Transaction Management**: Handle deposits, withdrawals, and transfers across different ledgers
- **React Hooks & Components**: Ready-to-use React components for wallet connectivity

## 🏗️ Architecture Overview

The library uses a modular architecture designed for flexibility, security, and ease of integration:

### Core Components

- **Authentication Module**: Handles user authentication through multiple providers
- **Currency Managers**: Type-specific handlers for different token standards
- **Ledger Interfaces**: Standardized interfaces for interacting with various IC ledgers
- **Context Providers**: React context providers for authentication and currency configuration
- **Hooks & Utilities**: Helper functions and React hooks for common currency operations

## 🛠️ Technical Components

### Authentication System

The library supports multiple authentication methods:

```
Authentication
├── Internet Identity
├── Web3Auth
└── Sign-In with Bitcoin (SIWB)
```

### Currency Management

Currency types are managed through a structured hierarchy:

```
CurrencyType
├── Real
│   ├── ICP
│   ├── GenericICRC1
│   ├── CKETHToken
│   │   ├── ETH
│   │   ├── USDC
│   │   ├── USDT
│   └── BTC
└── Fake (for in-game currencies)
```

## 📋 Prerequisites

- Node.js (version 18 or later)
- React (version 19 or later)
- Internet Computer SDK (dfx version 0.24.2 or later)
- Various IC canister interfaces (CKBTC, CKETH, etc.)

## 🚀 Getting Started

### Backend Usage (Rust Canister)

The currency library provides robust support for handling multiple cryptocurrencies within your backend canisters. Here's how to implement it:

#### 1. Initialize the Currency Manager

The `CurrencyManager` is the central component that handles different currencies. Initialize it based on your canister's needs:

```rust
use currency::types::currency_manager::CurrencyManager;
use currency::Currency;

// Initialize a new currency manager
let mut currency_manager = CurrencyManager::new();

// Add the currencies you want to support
currency_manager.add_currency(Currency::ICP).await?;
currency_manager.add_currency(Currency::BTC).await?;
currency_manager.add_currency(Currency::CKETHToken(CKTokenSymbol::USDC)).await?;
```

#### 2. Set Up Transaction State

The library uses a transaction state to keep track of processed transactions:

```rust
use currency::state::TransactionState;

// Initialize the transaction state
let mut transaction_state = TransactionState::new();
```

#### 3. Handle Deposits

Example of how to process a user's deposit (typically called when a user joins a table or deposits funds):

```rust
// When a user deposits to your canister
async fn handle_user_deposit(
    currency: Currency,
    user_principal: Principal,
    amount: u64,
) -> Result<(), CurrencyError> {
    // First validate that the user has given sufficient allowance
    currency_manager
        .validate_allowance(&currency, user_principal, amount)
        .await?;
    
    // Then process the deposit using the allowance
    currency_manager
        .deposit(&mut transaction_state, &currency, user_principal, amount)
        .await?;
    
    // Update your internal state as needed
    // ...
    
    Ok(())
}
```

#### 4. Handle Withdrawals

Withdrawing funds back to a user's wallet:

```rust
async fn withdraw_funds(
    currency: Currency,
    user_principal: Principal,
    amount: u64,
) -> Result<(), CurrencyError> {
    // Check if withdrawal is allowed by your business logic
    // ...
    
    // Process the withdrawal
    currency_manager
        .withdraw(&currency, user_principal, amount)
        .await?;
    
    // Update your internal state as needed
    // ...
    
    Ok(())
}
```

#### 5. Check User Balances

Query a user's balance on the ledger:

```rust
async fn get_user_balance(
    currency: Currency,
    user_principal: Principal,
) -> Result<u128, CurrencyError> {
    let balance = currency_manager
        .get_balance(&currency, user_principal)
        .await?;
    
    Ok(balance)
}
```

#### 6. Handling Generic ICRC-1 Tokens

For handling any ICRC-1 compatible token:

```rust
// Create a Token definition
let custom_token = Token::from_string(
    Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap(), // Ledger canister ID
    "MYTOK",                                                      // Symbol
    8                                                             // Decimals
);

// Add it to the currency manager
currency_manager
    .add_currency(Currency::GenericICRC1(custom_token))
    .await?;
```

### Frontend Usage (React)

#### Installation

```bash
npm install @zk-game-dao/currency
```

#### Basic Usage

1. Import and wrap your application with the currency context provider:

```jsx
import { ProvideCurrencyContext } from '@zk-game-dao/currency';

function App() {
  return (
    <ProvideCurrencyContext>
      <YourApplication />
    </ProvideCurrencyContext>
  );
}
```

2. Use authentication hooks to manage user login:

```jsx
import { useAuth } from '@zk-game-dao/currency';

function LoginButton() {
  const { login, isLoggingIn } = useAuth();
  
  return (
    <button 
      onClick={() => login('google')} 
      disabled={isLoggingIn}
    >
      {isLoggingIn ? 'Logging in...' : 'Login with Google'}
    </button>
  );
}
```

3. Access currency managers for token operations:

```jsx
import { useTokenManager, Currency } from '@zk-game-dao/currency';

function BalanceDisplay() {
  const icpManager = useTokenManager({ ICP: null });
  const [balance, setBalance] = useState(0);
  
  useEffect(() => {
    async function fetchBalance() {
      const accountBalance = await icpManager.accountBalance();
      setBalance(accountBalance);
    }
    
    if (icpManager) {
      fetchBalance();
    }
  }, [icpManager]);
  
  return <div>ICP Balance: {balance}</div>;
}
```

## 📁 Library Structure

```
.
├── package.json               # Package configuration
├── ui/                        # React components and hooks
│   ├── auth/                  # Authentication components
│   ├── components/            # UI components
│   ├── context/               # React context providers
│   ├── hooks/                 # React hooks
│   ├── icons/                 # Token and UI icons
│   ├── queries/               # API query functions
│   ├── types/                 # TypeScript type definitions
│   └── utils/                 # Utility functions
└── src/                       # Rust backend integration
    ├── types                  # Type definitions
    ├── lib.rs                 # Main library entry point
    ├── query.rs               # Ledger query functions
    ├── transfer.rs            # Transfer functions
    ├── currency_error.rs      # Error handling
    ├── state.rs               # Transaction state management
    ├── canister_wallet.rs     # Wallet interfaces
    └── ...
```

## 🔄 Usage Examples

### Backend Examples

#### Creating a Wallet for Multiple Currencies

```rust
// Initialize wallet support for multiple currencies
let mut currency_manager = CurrencyManager::new();

// Adding ICP support is automatic with new()
// Add support for USDC
currency_manager.add_currency(Currency::CKETHToken(CKTokenSymbol::USDC)).await?;

// Add support for a generic ICRC-1 token
let custom_token = Token::from_string(
    Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai").unwrap(),
    "CUSTOM",
    8
);
currency_manager.add_currency(Currency::GenericICRC1(custom_token)).await?;
```

#### Processing Withdrawals with Rake

```rust
// Example for processing a game with rake collection
async fn process_game_end(
    winner_principal: Principal,
    pot_amount: u64,
    rake_amount: u64,
    currency: Currency
) -> Result<(), CurrencyError> {
    // Withdraw winnings minus rake to the winner
    currency_manager
        .withdraw(&currency, winner_principal, pot_amount - rake_amount)
        .await?;
    
    // Transfer the rake to a rake wallet
    currency_manager
        .withdraw_rake(&currency, RAKE_WALLET_PRINCIPAL, rake_amount)
        .await?;
        
    Ok(())
}
```

### Frontend Examples

#### Authentication

```typescript
import { useAuth } from '@zk-game-dao/currency';

// Login with Internet Identity
const { login } = useAuth();
await login('ii');

// Login with Web3Auth
await login('google');  // or 'facebook', 'twitter', etc.

// Login with Bitcoin (SIWB)
await login('siwb');

// Get current authentication data
const { authData } = useAuth();
if (authData) {
  console.log('Logged in as:', authData.principal.toString());
}
```

#### Transfer Funds

```typescript
import { Principal } from '@dfinity/principal';
import { transferTo, type AuthData } from '@zk-game-dao/currency';

async function sendFunds(authData: AuthData) {
  const recipient = Principal.fromText('aaaaa-aa');
  const amount = 100000000n; // 1 ICP
  
  const blockHeight = await transferTo({ Real: { ICP: null } }, recipient, amount, authData);
  
  console.log('Transfer successful! Block height:', blockHeight);
}
```

## 🛣️ Roadmap

- [ ] Integrate with more authentication providers
- [ ] Add transaction history based on ledger transactions
- [ ] Enhance wallet management features
- [ ] Support for additional ICRC standards
- [ ] Improved security features for semi-custodial operations

## 📄 License

This project is licensed under the [Apache License 2.0](LICENSE).  
You are free to use, modify, and distribute this software under the terms of the Apache 2.0 license.  
See the `LICENSE` file for more details.
