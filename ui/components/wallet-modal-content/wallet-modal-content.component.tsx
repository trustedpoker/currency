import { DropdownComponent, List, ModalBackButtonPortal, ModalTitlePortal } from '@zk-game-dao/ui';
import { Fragment, memo, useMemo, useState } from 'react';

import { useAuth } from '../../auth/types/context';
import { useIsBTC } from '../../context';
import { useTokenRegistry } from '../../context/token-registry.context';
import { Currency } from '../../types/currency';
import { CurrencySerializer } from '../../utils/serialize';
import { AddTokenModal } from '../add-token-modal/add-token-modal.component';
import { CurrencyTypeComponent } from '../currency-type/currency-type.component';
import { ModalProps } from './context';
import { SelectedWalletContent } from './selected-wallet-content.component';
import { WalletItem } from './wallet-item.component';
import { ProvideWalletModalContext } from './wallet-modal.context';

export const WalletModalContent = memo<ModalProps>(({ onBack, onSubmit, requiredBalance }) => {
  const isBTC = useIsBTC();
  const [_currency, setCurrency] = useState<Currency | undefined>(
    requiredBalance?.currencyType === undefined || 'Fake' in requiredBalance.currencyType ? undefined : requiredBalance?.currencyType.Real);
  const currency = useMemo(() => isBTC ? { BTC: null } : _currency, [_currency, isBTC]);

  const { authData } = useAuth();

  const [isAddingToken, setIsAddingToken] = useState(false);

  const registry = useTokenRegistry();

  if (!authData) return <p>No principal or account found</p>;

  return (
    <ProvideWalletModalContext
      onBack={onBack}
      onSubmit={onSubmit}
      requiredBalance={requiredBalance}
      currency={currency}
    >
      <AddTokenModal isOpen={isAddingToken} onClose={() => setIsAddingToken(false)} />
      {!currency ? (
        <Fragment key="no currency">
          <ModalTitlePortal>Wallet</ModalTitlePortal>
          <List
            label="Tokens"
            ctas={[
              { label: "Add a token", onClick: () => setIsAddingToken(true) },
            ]}
          >
            {registry.highlightedCurrencies.map(Real => (
              <WalletItem key={CurrencySerializer.serialize(Real)} currency={Real} onClick={() => setCurrency(Real)} />
            ))}
          </List>
        </Fragment>
      ) : (
        <Fragment key="Currency">
          {isBTC ?
            <ModalTitlePortal>
              You BTC wallet
            </ModalTitlePortal> :
            (
              <>
                <ModalTitlePortal >
                  <DropdownComponent
                    options={
                      registry.highlightedCurrencies.map(v => ({
                        value: CurrencySerializer.serialize(v),
                        label: <CurrencyTypeComponent currencyType={{ Real: v }} />,
                      }))
                    }
                    value={CurrencySerializer.serialize(currency)}
                    onChange={v => setCurrency(typeof v === 'string' ? CurrencySerializer.deserialize(v) : undefined)}
                  />
                </ModalTitlePortal>
                <ModalBackButtonPortal onClick={() => setCurrency(undefined)}>
                  Wallet
                </ModalBackButtonPortal>
              </>
            )}
          <SelectedWalletContent currency={currency} onBack={() => setCurrency(undefined)} />

        </Fragment>
      )}
    </ProvideWalletModalContext>
  );
});
