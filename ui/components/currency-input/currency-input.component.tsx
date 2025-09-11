import Big from 'big.js';
import { memo, useCallback, useMemo } from 'react';

import { BigIntToBig, BigToBigInt, NumberInputComponent, NumberInputValue } from '@zk-game-dao/ui';

import { useCurrencyManagerMeta } from '../../hooks/currency-manager.hook';
import { CurrencyType } from '../../types/currency';
import { CurrencyTypeSerializer } from '../../utils';
import { CurrencyMetaIconComponent, CurrencyTypeIconComponent } from '../token-icon/token-icon.component';

export type CurrencyInputProps = Omit<NumberInputValue, 'minQuickAction' | 'maxQuickAction' | 'step' | 'maxDecimals' | 'symbol' | 'defaultValue' | 'min' | 'max'> & {
  currencyType: CurrencyType;
  onChange?(value: bigint): void;
  value?: bigint;
  defaultValue?: bigint;
  min?: bigint;
  max?: bigint;
  className?: string;
  hideMinQuickAction?: boolean;
  hideMaxQuickAction?: boolean;
};

export const CurrencyInputComponent = memo<CurrencyInputProps>(
  ({
    currencyType,
    onChange,
    value,
    defaultValue,
    min,
    hideMinQuickAction,
    hideMaxQuickAction,
    max,
    ...props
  }) => {
    const _meta = useCurrencyManagerMeta(currencyType);
    const meta = useMemo(() => {
      if ('alternatives' in _meta && _meta.alternatives && Object.values(_meta.alternatives).length > 0)
        return Object.values(_meta.alternatives)[0] ?? _meta;
      return _meta;
    }, [_meta]);

    const step = useMemo(() => {
      if (meta.decimals === 0) return Big(1);
      if ('Real' in currencyType && 'BTC' in currencyType.Real)
        return Big(0.00000001);
      if (meta.renderedDecimalPlaces !== undefined)
        return Big(1 / Math.pow(10, meta.renderedDecimalPlaces));
      return Big(0.0001);
    }, [meta.renderedDecimalPlaces, CurrencyTypeSerializer.serialize(currencyType)]);

    const f2b = useCallback((v?: Big) => v === undefined ? undefined : BigToBigInt(v, meta.decimals), [meta.decimals]);
    const b2f = useCallback((v?: bigint) => v === undefined ? undefined : BigIntToBig(v, meta.decimals), [meta.decimals]);

    return (
      <NumberInputComponent
        {...props}
        step={step}
        maxDecimals={meta.decimals}
        min={b2f(min)}
        max={b2f(max)}
        symbol={<div className='flex justify-center items-center -mt-0.5'><CurrencyMetaIconComponent meta={meta} className='size-4 flex' /></div>}
        value={b2f(value)}
        defaultValue={b2f(defaultValue)}
        hideClear
        onChangeBigFloat={onChange && (v => onChange(f2b(v) ?? 0n))}
        minQuickAction={!hideMinQuickAction}
        maxQuickAction={!hideMaxQuickAction}
      />
    );
  },
);
