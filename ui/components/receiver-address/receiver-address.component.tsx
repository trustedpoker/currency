import { memo, useMemo } from 'react';

import { Allowance } from '@dfinity/ledger-icrc/dist/candid/icrc_ledger';
import {
  BigIntToString, DropdownInputComponent, List, ListItem, LoadingSpinnerComponent,
  NumberInputComponent, TextInputComponent
} from '@zk-game-dao/ui';
import { Currency, CurrencyType } from '../../types/currency';
import { useWalletModalContentContext } from '../wallet-modal-content/context';
import { useChainFusionAllowance, useChainFusionTransactionFees, useSetAllowance, useShowingNativeCurrency } from '../../types/chain-fusion.context';
import { useEIP6963 } from '../../types/EIP6963.context';
import { WalletType, WalletTypeLabel, WalletTypes } from '../wallet-type-label/wallet-type-label.component';
import { CurrencySerializer } from '../../utils/serialize';
import { CurrencyComponent } from '../currency/currency.component';
import { CurrencyTypeSymbolComponent } from '../currency-type/currency-type.component';
import { useTransactionFee } from '../../hooks/transaction-fee';
import { useCurrencyManagerMeta, useRequiredCurrencyManager } from '../../hooks/currency-manager.hook';
import { useBalance } from '../../hooks/balance';
import { TokenAmountToBig } from '../../utils/token-amount-conversion';
import { CurrencyTypeIconComponent } from '../token-icon/token-icon.component';

const WalletSelectionComponent = memo<{ currency: Currency; }>(({ currency }) => {
  const { web3WalletType, setWeb3WalletType, mode, web3WithdrawExternalWalletAddress, setWeb3WithdrawExternalWalletAddress } = useWalletModalContentContext();

  const isShowingEthCurrency = useShowingNativeCurrency(currency);

  const { selectedWallet, wallets, connectWallet } = useEIP6963();

  if (!isShowingEthCurrency)
    return (
      <>
        <DropdownInputComponent
          label={mode === "deposit" ? "From" : "To"}
          value={web3WalletType}
          options={[
            ...WalletTypes.map((value) => ({
              label: <WalletTypeLabel walletType={value} />,
              value,
            })),
            { label: "External wallet", value: "external" },
          ]}
          onChange={(v) => setWeb3WalletType(v as WalletType | "external")}
        />
        {!isShowingEthCurrency && web3WalletType === "external" && mode === "withdraw" && (
          <TextInputComponent
            label="External account ID or principal"
            value={web3WithdrawExternalWalletAddress}
            onChange={setWeb3WithdrawExternalWalletAddress}
          />
        )}
      </>
    );

  if (Object.keys(wallets).length === 0)
    return (
      <p className='text-left type-subheadline pl-4'>
        Please install <a href="https://metamask.io/" target='_blank' className='underline hover:no-underline'>MetaMask</a>,  <a href="https://trustwallet.com/" className='underline hover:no-underline' target='_blank'>Trust Wallet</a>,  <a href="https://www.okx.com/" className='underline hover:no-underline' target='_blank'>OKX</a> or any other <a href="https://eip6963.org/" className='underline hover:no-underline' target="_blank">EIP-6963 compatible wallet</a>
      </p>
    );

  return (
    <>
      <DropdownInputComponent
        label={mode === "deposit" ? "From" : "To"}
        value={selectedWallet?.info.rdns}
        options={(Object.entries(wallets)).map(([value, { info }]) => ({ label: <WalletTypeLabel eip6963={info} />, value }))}
        onChange={v => connectWallet(v as string)}
      />
    </>
  );
}, (prev, next) => CurrencySerializer.serialize(prev.currency) === CurrencySerializer.serialize(next.currency));

const AllowanceDisplayComponent = memo<{ allowance: Allowance | undefined; currencyType: CurrencyType }>(({ allowance, currencyType }) => {
  return (
    <ListItem
      rightLabel={
        allowance ?
          <CurrencyComponent
            currencyType={currencyType}
            variant="inline"
            currencyValue={allowance.allowance}
          /> :
          <LoadingSpinnerComponent />
      }
    >
      <CurrencyTypeSymbolComponent currencyType={currencyType} /> allowance
    </ListItem>
  );
}, (prev, next) => JSON.stringify(prev) === JSON.stringify(next));

const AllowanceComponent = memo<{ currency: Currency }>(({ currency }) => {
  const allowance = useChainFusionAllowance(currency);
  const allowanceEth = useChainFusionAllowance({ CKETHToken: { ETH: null } });
  const setAllowance = useSetAllowance(currency);

  if (!allowance || !allowanceEth) return <></>
  if (allowanceEth.allowance + allowance.allowance === 0n) return <></>

  return (
    <div>
      <p className="type-callout text-material-medium-2 mr-auto mb-2">
        Allowance
      </p>
      <List>
        <AllowanceDisplayComponent allowance={allowance} currencyType={{ Real: currency }} />
        {allowance && allowance.allowance > 0n && (
          <ListItem onClick={() => setAllowance(0n)}>
            Withdraw allowance
          </ListItem>
        )}
      </List>
    </div>
  );
});

export const ReceiverSelectorComponent = memo<{ currency: Currency }>(({ currency }) => {

  const { amount, setAmount, mode } = useWalletModalContentContext();

  const transactionFee = useTransactionFee({ Real: currency });
  const { meta: { thousands } } = useRequiredCurrencyManager({ Real: currency });
  const walletBalance = useBalance({ Real: currency });

  const isShowingEthCurrency = useShowingNativeCurrency(currency);
  const { selectedWallet } = useEIP6963();
  const fees = useChainFusionTransactionFees();
  const meta = useCurrencyManagerMeta({ Real: currency });

  const isEth = useMemo(() => 'CKETHToken' in currency && "ETH" in currency.CKETHToken, [currency]);

  if (!fees)
    return <LoadingSpinnerComponent />;

  return (
    <>
      {isShowingEthCurrency && <AllowanceComponent currency={currency} />}
      <List key={(isShowingEthCurrency ? `Eth-${mode}` : 'IC')}>
        <NumberInputComponent
          label="Amount"
          value={Number(amount) / thousands}
          onChange={(v) =>
            setAmount(BigInt(Math.floor((v as number) * thousands)))
          }
          min={0}
          max={
            mode === "deposit"
              ? undefined
              : TokenAmountToBig(
                walletBalance,
                meta,
              )
          }
          symbol={
            <CurrencyTypeIconComponent className="w-[24px] h-[24px] mr-1" currencyType={{ Real: currency }} />
          }
        />
        {!isShowingEthCurrency ? (
          <ListItem
            rightLabel={
              <CurrencyComponent
                currencyType={{ Real: currency }}
                variant="inline"
                currencyValue={transactionFee}
              />
            }
          >
            Fee
          </ListItem>
        ) : (
          <>
            {mode === 'withdraw' && (
              <ListItem
                rightLabel={
                  fees[isEth ? 'ckETHToETH' : 'ckERC20ToERC20'] > 1000000n ?
                    <CurrencyComponent
                      currencyType={{ Real: { CKETHToken: { ETH: null } } }}
                      variant="inline"
                      currencyValue={fees[isEth ? 'ckETHToETH' : 'ckERC20ToERC20']}
                    /> :
                    <span>
                      {BigIntToString(fees[isEth ? 'ckETHToETH' : 'ckERC20ToERC20'], 9)} gwei
                    </span>
                }
              >
                Fee
              </ListItem>
            )}
          </>
        )}
        <WalletSelectionComponent currency={currency} />
      </List >
      {amount > 0n && isShowingEthCurrency && selectedWallet && (
        <List variant={{ type: 'default', readonly: true, variant: 'alert' }} key={currency + mode}>
          {isEth && <ListItem className='text-sm'>The minimum withdrawal for eth is 0.03.</ListItem>}
          {mode === 'deposit' ? (
            <>
              <ListItem className='text-sm'>Make sure to leave the this modal open until both the spending cap and the transfer requests on your {selectedWallet.info.name} wallet are approved.</ListItem>
              <ListItem className='text-sm'>After the transfer has been submitted it will take up to 20 minutes for your <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} /> to arrive.</ListItem>
            </>
          ) : (
            <ListItem className='text-sm'>
              ChainFusion will mint the wrapped <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} />. This process can take up to 20 minutes.
            </ListItem>
          )}
        </List>
      )
      }
    </>
  );
}, (prev, next) => CurrencySerializer.serialize(prev.currency) === CurrencySerializer.serialize(next.currency));
