import { Fragment, memo, useEffect } from 'react';

import {
  ButtonComponent, ErrorComponent, FauxLoadingBarAnimationComponent, ModalFooterPortal,
  TabsComponent, useIsMobile
} from '@zk-game-dao/ui';

import { useCurrencyManager } from '../../hooks/currency-manager.hook';
import { useShowingNativeCurrency } from '../../types/chain-fusion.context';
import { Currency } from '../../types/currency';
import { useManualWalletTransfer } from '../../types/manual-wallet-context';
import { CurrencySerializer } from '../../utils/serialize';
import { ReceiverSelectorComponent } from '../receiver-address/receiver-address.component';
import { WalletDisplayComponent } from '../wallet-display/wallet-display.component';
import { BTCWalletComponent } from '../btc-wallet/btc-wallet.component';
import { useWalletModalContentContext } from './context';

export const SelectedWalletContent = memo<{
  currency: Currency;
  onBack(): void;
}>(({ currency, onBack }) => {
  const { requiredBalance, mode, setMode, web3WalletType, authData, withdraw, deposit, continueMutation } = useWalletModalContentContext();
  const isMobile = useIsMobile();
  const isShowingEthCurrency = useShowingNativeCurrency(currency);
  const depositToZKPFromManual = useManualWalletTransfer(
    { Real: currency },
    authData?.principal,
  );

  if ('BTC' in currency)
    return <BTCWalletComponent onBack={onBack} />;

  return (
    <>
      <div className="gap-3 flex flex-col">
        <p className="type-callout text-material-medium-2">Your ZKP wallet</p>
        <WalletDisplayComponent currency={currency} />

        <Fragment>
          {!isMobile && !requiredBalance && (
            <TabsComponent
              tabs={[
                { label: "Deposit", value: "deposit" },
                { label: "Withdraw", value: "withdraw" },
              ]}
              value={mode}
              onChange={(v) => setMode(v)}
            />
          )}

          {isMobile && mode === "withdraw" && <p>Withdraw</p>}
          <ReceiverSelectorComponent currency={currency} />

          {mode === "deposit" && web3WalletType === "external" && !isShowingEthCurrency && (
            <p className="type-callout text-material-medium-2">
              Use your external wallet to deposit funds to your ZKP wallet
            </p>
          )}

          <ErrorComponent
            error={
              depositToZKPFromManual.error || withdraw.error || deposit.error
            }
          />

          {deposit.isPending ||
            (depositToZKPFromManual.isPending && (
              <FauxLoadingBarAnimationComponent />
            ))}

          <ModalFooterPortal>
            <ButtonComponent variant="naked" onClick={onBack}>
              Cancel
            </ButtonComponent>
            {mode === "deposit" ? (
              <ButtonComponent
                onClick={deposit.mutateAsync}
                isLoading={
                  deposit.isPending || depositToZKPFromManual.isPending
                }
              >
                Deposit
              </ButtonComponent>
            ) : (
              <ButtonComponent
                onClick={withdraw.mutateAsync}
                isLoading={withdraw.isPending}
              >
                Withdraw
              </ButtonComponent>
            )}
          </ModalFooterPortal>
        </Fragment>
      </div>

      {requiredBalance && (
        <>
          <ErrorComponent error={continueMutation.error} />
          <ModalFooterPortal>
            <ButtonComponent variant="naked" onClick={onBack}>
              Cancel
            </ButtonComponent>
            <ButtonComponent
              onClick={continueMutation.mutateAsync}
              isLoading={continueMutation.isPending}
            >
              Continue
            </ButtonComponent>
          </ModalFooterPortal>
        </>
      )}
    </>
  );
}, (prev, next) => CurrencySerializer.serialize(prev.currency) === CurrencySerializer.serialize(next.currency) && prev.onBack === next.onBack);
