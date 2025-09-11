import { addMinutes } from 'date-fns';
import { AnimatePresence } from 'framer-motion';
import { useSiwbIdentity } from 'ic-siwb-lasereyes-connector';
import { memo } from 'react';

import { useLaserEyes } from '@omnisat/lasereyes';
import {
  ButtonComponent, ErrorComponent, Label, ModalFooterPortal, SwitchInputComponent, TabsComponent,
  TextInputComponent, useMutation, usePersistentState, UserError
} from '@zk-game-dao/ui';

import {
  SWIB_WALLET_MAPPING
} from '../../auth/components/provide-btc-logins/provide-btc-logins.component';
import { useAllowance, useBalance } from '../../hooks';
import { useBTCDepositAddress, useBTCMinter, useBTCWithdrawalAccount, useMinterInfo } from '../../hooks/btc';
import { CurrencyInputComponent } from '../currency-input';
import { CurrencyComponent } from '../currency/currency.component';
import { WalletDisplayComponent } from '../wallet-display/wallet-display.component';
import { useWalletModalContentContext } from '../wallet-modal-content/context';
import { BTCWalletTransactions } from './btc-wallet-transactions.component';

export const BTCWalletComponent = memo<{ onBack(): void; }>(({ onBack }) => {
  const { requiredBalance, mode, amount, setAmount, setMode, authData, continueMutation } = useWalletModalContentContext();
  const lazereyes = useLaserEyes();

  const [useLazereyesForTransfer, setUseLazereyesForTransfer] = usePersistentState('use-lazereyes-for-transfer', true);
  const [manualAddress, setManualAddress] = usePersistentState('manual-btc-address', lazereyes.address);

  const siwb = useSiwbIdentity();
  const minter = useBTCMinter();
  const minterInfo = useMinterInfo();
  const { data: depositBTCAddress } = useBTCDepositAddress();
  const { data: withdrawalAccount } = useBTCWithdrawalAccount();

  const approval = useAllowance(!withdrawalAccount ? undefined : {
    currencyType: { Real: { BTC: null } },
    receiver: { principal: withdrawalAccount.owner },
    name: 'BTC Minter',
  });
  const balance = useBalance({ Real: { BTC: null } });

  const withdraw = useMutation({
    mutationFn: async () => {
      await approval.require({ amount, reason: 'Withdraw BTC' }, addMinutes(new Date(), 20));

      if (useLazereyesForTransfer) {
        if (!manualAddress)
          throw new Error('No address found');
        return minter.retrieveBtcWithApproval({ address: manualAddress, amount });
      }

      if (!lazereyes.address)
        throw new Error('No address found');

      return minter.retrieveBtcWithApproval({ address: lazereyes.address, amount });
    },
  });

  const deposit = useMutation({
    mutationFn: async () => {
      if (!useLazereyesForTransfer)
        throw new UserError('You need to use Lazereyes for auto deposit');

      if (!depositBTCAddress)
        throw new Error('No deposit address found');

      return lazereyes.sendBTC(depositBTCAddress, Number(amount));
    },
  });

  if (authData.type !== 'siwb')
    return null;

  return (
    <div className="gap-3 flex flex-col">
      <AnimatePresence>

        <div className='flex flex-col gap-2 mb-6'>
          <Label>Balance</Label>
          <CurrencyComponent
            currencyType={{ Real: { BTC: null } }}
            currencyValue={balance}
            key="balance"
            className='p-4 bg-material-main-1 rounded-[12px] w-full'
            size='big'
          />
        </div>

        {depositBTCAddress && (
          <BTCWalletTransactions
            requiredConfirmations={minterInfo.data.min_confirmations}
            btcAddress={depositBTCAddress}
          />
        )}

        {!requiredBalance && (
          <TabsComponent
            tabs={[
              { label: "Deposit", value: "deposit" },
              { label: "Withdraw", value: "withdraw" },
            ]}
            value={mode}
            onChange={(v) => setMode(v)}
            key="tabs"
          />
        )}

        <SwitchInputComponent
          label={`Use your ${SWIB_WALLET_MAPPING[authData.provider.provider].label} wallet`}
          checked={useLazereyesForTransfer}
          onChange={setUseLazereyesForTransfer}
          key="lazereyes-switch"
        />

        {mode === 'withdraw' && (
          <CurrencyInputComponent
            key="withdraw"
            currencyType={{ Real: { BTC: null } }}
            label="Amount"
            value={amount}
            min={minterInfo.data.retrieve_btc_min_amount}
            max={balance}
            onChange={setAmount}
          />
        )}

        {mode === 'withdraw' && (
          <div className="opacity-70 flex flex-row px-4">
            Minimum withdrawal is <CurrencyComponent className='flex mx-1' currencyType={{ Real: { BTC: null } }} currencyValue={minterInfo.data.retrieve_btc_min_amount} />
          </div>
        )}

        {(mode === 'deposit' && useLazereyesForTransfer) && (
          <CurrencyInputComponent
            key="deposit"
            currencyType={{ Real: { BTC: null } }}
            label="Amount"
            value={amount}
            min={1n}
            onChange={setAmount}
          />
        )}

        {!useLazereyesForTransfer && mode === 'deposit' &&
          <WalletDisplayComponent key="wallet-display" currency={{ BTC: null }} />
        }

        {!useLazereyesForTransfer && mode === 'withdraw' && (
          <TextInputComponent
            key="manual-btc-address"
            label="Receiver BTC address"
            value={manualAddress}
            onChange={(v) => setManualAddress(v)}
          />
        )}

        {withdraw.error && <ErrorComponent title="Withdrawal error" error={withdraw.error} />}
        {deposit.error && <ErrorComponent title="Deposit error" error={deposit.error} />}
      </AnimatePresence >

      <ModalFooterPortal>
        <ButtonComponent variant="naked" onClick={onBack}>
          Cancel
        </ButtonComponent>
        {mode === "deposit" && useLazereyesForTransfer && (
          <ButtonComponent
            onClick={deposit.mutateAsync}
            isLoading={deposit.isPending}
          >
            Deposit
          </ButtonComponent>
        )}
        {mode === 'withdraw' && (
          <ButtonComponent
            onClick={withdraw.mutateAsync}
            isLoading={withdraw.isPending}
          >
            Withdraw
          </ButtonComponent>
        )}
      </ModalFooterPortal>
    </div>
  );
});