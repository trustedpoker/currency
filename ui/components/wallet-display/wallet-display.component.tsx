import { useSiwbIdentity } from 'ic-siwb-lasereyes-connector';
import { memo, useMemo } from 'react';

import {
  CopiableTextComponent, Interactable, List, ListItem, QRCodeComponent
} from '@zk-game-dao/ui';

import { useBalance } from '../../hooks/balance';
import {
  useChainFusion, useIsChainFusionCurrency, useShowingNativeCurrency
} from '../../types/chain-fusion.context';
import { Currency } from '../../types/currency';
import { CurrencySerializer } from '../../utils/serialize';
import { CurrencyTypeSymbolComponent } from '../currency-type/currency-type.component';
import { CurrencyComponent } from '../currency/currency.component';
import { useWalletModalContentContext } from '../wallet-modal-content/context';
import { BTCWalletDisplayComponent } from './btc-wallet-display.component';

export const WalletDisplayComponent = memo<{ currency: Currency; }>(({ currency }) => {
  const { isNativeShown, setIsNativeShown } = useChainFusion();
  const { authData } = useWalletModalContentContext();
  const walletBalance = useBalance(currency ? { Real: currency } : { Fake: null });
  const isShowingNativeCurrency = useShowingNativeCurrency(currency);
  const isChainFusionCurrency = useIsChainFusionCurrency(currency)
  const siwb = useSiwbIdentity();

  const qrValue = useMemo(() => {
    if (!isNativeShown) return "";
    return authData.principal.toText();
  }, [isNativeShown, authData.principal.toText()]);

  if ('BTC' in currency)
    return <BTCWalletDisplayComponent />;

  if (isShowingNativeCurrency)
    return (
      <>
        <ListItem
          rightLabel={
            <CurrencyComponent
              currencyType={currency ? { Real: currency } : { Fake: null }}
              variant="inline"
              currencyValue={walletBalance}
            />
          }
        >
          Balance
        </ListItem>
        <div
          className="type-subheadline text-material-medium-1 px-4 w-full text-start"
        >
          This currency is wrapped into <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} /> using Chain Fusion.{' '}
          <Interactable className='inline underline hover:no-underline' onClick={() => setIsNativeShown(false)}>Use <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} /> instead</Interactable>
        </div>
      </>
    );

  return (
    <>
      <div className="flex flex-col lg:flex-row gap-3 lg:items-center" key="ICP-NATIVE">
        <QRCodeComponent className="lg:flex hidden" value={qrValue} />
        <List>
          <ListItem
            rightLabel={
              <CopiableTextComponent text={authData.principal.toText()} />
            }
          >
            Principal
          </ListItem>
          <ListItem
            rightLabel={
              <CopiableTextComponent
                text={authData.accountIdentifier.toHex()}
              />
            }
          >
            <span className="whitespace-nowrap">Account ID</span>
          </ListItem>
          <ListItem
            rightLabel={
              <CurrencyComponent
                currencyType={{ Real: currency }}
                variant="inline"
                currencyValue={walletBalance}
              />
            }
          >
            Balance
          </ListItem>
        </List>
      </div>

      {isChainFusionCurrency && (
        <div
          className="type-subheadline text-material-medium-1 px-4 w-full text-start"
        >
          You are seeing the wrapped <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} /> using Chain Fusion.{' '}
          <Interactable className='inline underline hover:no-underline' onClick={() => setIsNativeShown(true)}>Use native <CurrencyTypeSymbolComponent currencyType={{ Real: currency }} /> instead</Interactable>
        </div>
      )}
    </>
  );
}, (prev, next) => CurrencySerializer.serialize(prev.currency) === CurrencySerializer.serialize(next.currency));
