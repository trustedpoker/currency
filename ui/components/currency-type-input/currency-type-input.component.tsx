import { DropdownInputComponent } from '@zk-game-dao/ui';
import { memo, ReactNode, useEffect, useMemo, useState } from 'react';

import { useTokenRegistry } from '../../context/token-registry.context';
import { Currency, CurrencyType } from '../../types/currency';
import { CurrencyTypeSerializer } from '../../utils/serialize';
import { AddTokenModal } from '../add-token-modal/add-token-modal.component';
import { CurrencyTypeComponent } from '../currency-type/currency-type.component';
import { useIsBTC } from '../../context/currency-config.context';

export const CurrencyTypeInputComponent = memo<{
  label?: ReactNode;
  value?: CurrencyType;
  onChange(value?: CurrencyType): void;
}>(({ label, value: _value, onChange: _onChange }) => {

  const value = useMemo(() => _value && CurrencyTypeSerializer.serialize(_value), [_value]);

  const onChange = (value?: string) =>
    _onChange(value ? CurrencyTypeSerializer.deserialize(value) : undefined);

  const { highlightedCurrencies, addCurrency } = useTokenRegistry();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const isBTC = useIsBTC();

  useEffect(() => {
    if (!isBTC) return;
    _onChange({ Real: { BTC: null } });
  }, [isBTC]);

  if (isBTC)
    return null;

  return (
    <>
      <AddTokenModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSelect={Real => {
          _onChange({ Real });
          addCurrency(Real);
          setIsModalOpen(false);
        }}
      />
      <DropdownInputComponent
        options={[
          { value: undefined as unknown as string, label: 'Select a token' },
          { value: CurrencyTypeSerializer.serialize({ Fake: null }), label: <CurrencyTypeComponent currencyType={{ Fake: null }} /> },
          ...(highlightedCurrencies.map(Real => ({
            value: CurrencyTypeSerializer.serialize({ Real }),
            label: <CurrencyTypeComponent currencyType={{ Real }} />,
          }))),
          {
            value: 'other',
            label: 'Other',
          }
        ]}
        label={label}
        value={value}
        onChange={v => {
          if (v === 'other') {
            setIsModalOpen(true);
          } else {
            onChange(v as string | undefined);
          }
        }}
      />
    </>
  );
});


export const RealCurrencyInputComponent = memo<{
  label?: ReactNode;
  value?: Currency;
  onChange(value?: Currency): void;
}>(({ value: _value, onChange: _onChange, label }) => {

  const value = useMemo(() => _value && CurrencyTypeSerializer.serialize({ Real: _value }), [_value]);

  const onChange = (value?: string) => {
    console.log({ value });
    if (value) {
      const currency = CurrencyTypeSerializer.deserialize(value);
      if ('Fake' in currency)
        throw new Error('Fake currency not allowed');
      _onChange(currency.Real);
    } else {
      _onChange(undefined);
    }
  };

  const [isModalOpen, setIsModalOpen] = useState(false);

  const { highlightedCurrencies, addCurrency } = useTokenRegistry();

  const isBTC = useIsBTC();

  useEffect(() => {
    if (!isBTC) return;
    _onChange({ BTC: null });
  }, [isBTC]);

  if (isBTC)
    return null;

  return (
    <>
      <AddTokenModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onSelect={Real => {
          _onChange(Real);
          addCurrency(Real);
          setIsModalOpen(false);
        }}
      />
      <DropdownInputComponent
        options={[
          { value: undefined as unknown as string, label: 'Select a token' },
          ...(highlightedCurrencies.map(Real => ({
            value: CurrencyTypeSerializer.serialize({ Real }),
            label: <CurrencyTypeComponent currencyType={{ Real }} />,
          }))),
          {
            value: 'other',
            label: 'Other',
          }
        ]}
        label={label}
        value={value}
        onChange={v => {
          if (v === 'other') {
            setIsModalOpen(true);
          } else {
            onChange(v as string | undefined);
          }
        }}
      />
    </>
  );
});