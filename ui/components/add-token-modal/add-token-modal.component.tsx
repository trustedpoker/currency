import { List, ListItem, LoadingAnimationComponent, Modal, ModalTitlePortal, SwitchInputComponent, TextInputComponent } from '@zk-game-dao/ui';
import { memo, useMemo, useState } from 'react';

import { useSearchCurrencies, useTokenRegistry } from '../../context/token-registry.context';
import { Currency } from '../../types/currency';
import { CurrencySerializer } from '../../utils/serialize';
import { CurrencyTypeComponent } from '../currency-type/currency-type.component';
import { useIsBTC } from '../../context';

export const AddTokenModal = memo<{
  onClose(): void;
  isOpen?: boolean;
  onSelect?(currency: Currency): void;
}>(({ onClose, isOpen, onSelect }) => {
  const registry = useTokenRegistry();
  const { addCurrency, removeCurrency } = registry;
  const [search, setSearch] = useState<string>();
  const isBTC = useIsBTC();

  const { data: tokens, isPending, isFetching, ...t } = useSearchCurrencies(search);

  const shownTokens = useMemo(() => {
    let all = search ? tokens : ([
      ...registry.allCurrencies,
      ...tokens,
    ]).filter((value, index, self) =>
      self.findIndex(c => CurrencySerializer.serialize(c) === CurrencySerializer.serialize(value)) === index
    );

    if (onSelect && !search)
      all = all.filter(c => !registry.highlightedCurrencies.some(h => CurrencySerializer.serialize(h) === CurrencySerializer.serialize(c)));

    return all.sort((a, b) => {
      const aHighlighted = registry.highlightedCurrencies.some(h => CurrencySerializer.serialize(h) === CurrencySerializer.serialize(a));
      const bHighlighted = registry.highlightedCurrencies.some(h => CurrencySerializer.serialize(h) === CurrencySerializer.serialize(b));
      if (aHighlighted !== bHighlighted) {
        return Number(bHighlighted) - Number(aHighlighted);
      }
      return CurrencySerializer.serialize(a).localeCompare(CurrencySerializer.serialize(b));
    });
  }, [registry.allCurrencies, tokens, search, registry.highlightedCurrencies, onSelect]);

  if (isBTC)
    return null;

  return (
    <Modal
      key="add-token-modal"
      title="Add a token"
      onClose={onClose}
      open={isOpen}
    >
      <ModalTitlePortal>Add a token</ModalTitlePortal>

      <TextInputComponent
        label="Search"
        placeholder='Search or paste a ledger address'
        onChange={setSearch}
        value={search}
      />

      {isFetching && shownTokens.length === 0 && <LoadingAnimationComponent variant="shimmer">Fetching ledgers</LoadingAnimationComponent>}

      {shownTokens.length === 0 && !isFetching && <p className="text-center text-gray-500">No tokens found</p>}
      {shownTokens.length > 0 && (
        <>
          {onSelect ? (
            <List label="Tokens">
              {shownTokens.map(Real => (
                <ListItem
                  onClick={() => onSelect(Real)}
                  key={CurrencySerializer.serialize(Real)}
                >
                  <CurrencyTypeComponent currencyType={{ Real }} />
                </ListItem>
              ))}
            </List>
          ) : (
            <List label="Tokens">
              {shownTokens.map(Real => (
                <SwitchInputComponent
                  label={<CurrencyTypeComponent currencyType={{ Real }} />}
                  checked={registry.highlightedCurrencies.some(c => CurrencySerializer.serialize(c) === CurrencySerializer.serialize(Real))}
                  onChange={v => (v ? addCurrency : removeCurrency)(Real)}
                  key={CurrencySerializer.serialize(Real)}
                />
              ))}
            </List>
          )}
        </>
      )}
    </Modal >
  );
});
