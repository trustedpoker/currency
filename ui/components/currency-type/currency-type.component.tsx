import { memo, useMemo } from 'react';

import { useCurrencyManagerMeta } from '../../hooks/currency-manager.hook';
import { CKTokenSymbol, CurrencyType, Token } from '../../types/currency';
import { CurrencyTypeToString } from '../../utils/currency-type-to-string';
import { CurrencyTypeIconComponent } from '../token-icon/token-icon.component';

export const CurrencyTypeLabelComponent = memo<{ currencyType: CurrencyType; }>(({ currencyType }) => {
  const { metadata } = useCurrencyManagerMeta(currencyType);
  const name = useMemo(() => metadata?.name ?? CurrencyTypeToString(currencyType), [metadata]);

  return <>{name.startsWith('ck') ? name.slice(2) : name}</>;
});

export const GenericICRC1LabelComponent = memo<{ value: Token; }>(({ value }) => <>{CurrencyTypeToString({ Real: { GenericICRC1: value } })}</>);
export const CKTokenSymbolLabelComponent = memo<{ value: CKTokenSymbol; }>(({ value }) => <>{CurrencyTypeToString({ Real: { CKETHToken: value } })}</>);
export const CurrencyTypeSymbolComponent = memo<{ currencyType: CurrencyType; }>(({ currencyType: value }) => <>{CurrencyTypeToString(value)}</>);

export const CurrencyTypeComponent = memo<{ currencyType: CurrencyType; }>(({ currencyType: value }) => (
  <div className='flex flex-row gap-2 justify-start items-center'>
    {value && <CurrencyTypeIconComponent className='size-5' currencyType={value} />}
    <CurrencyTypeSymbolComponent currencyType={value} />
  </div>
));
