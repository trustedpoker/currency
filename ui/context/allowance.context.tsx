import { memo, ReactNode, useMemo, useState } from 'react';

import {
  ButtonComponent, List, ListItem, Modal, ModalFooterPortal, UserError
} from '@zk-game-dao/ui';

import { CurrencyComponent } from '../components';
import { useAllowanceBalance } from '../hooks/allowance';
import { AllowanceContextType, CurrencyAllowanceContext, FullAllowanceRequestData } from '../types/allowance.context';

type AllowanceResolver = (FullAllowanceRequestData) & { resolve: () => void; reject: (e: Error) => void; expires_at: Date };

const ApprovalModal = memo<AllowanceResolver & { type: 'update' | 'require' }>(({ address, request, resolve, reject, type, expires_at }) => {

  const allowance = useAllowanceBalance(address);

  const ctaLabel = useMemo(() => {
    switch (type) {
      case 'update':
        if (request.amount === 0n) return 'Revoke';
        return 'Approve';
      case 'require':
        return 'Ok';
    }
  }, [type, request.amount]);

  return (
    <Modal
      open={true}
      onClose={() => reject(new UserError("User cancelled"))}
      title={request.reason}
    >
      <List>
        <ListItem rightLabel={('principal' in address.receiver) ? address.receiver.principal.toText() : address.receiver.accountIdentifier.toHex()}>
          {address.name} address
        </ListItem>
        <ListItem rightLabel={<CurrencyComponent currencyType={address.currencyType} currencyValue={allowance} />}>
          Current allowance
        </ListItem>
        <ListItem rightLabel={<CurrencyComponent currencyType={address.currencyType} currencyValue={request.amount} />}>
          {type === 'require' ? 'Required' : 'New'} allowance
        </ListItem>
      </List>

      <ModalFooterPortal>
        <ButtonComponent
          variant="naked"
          onClick={() => reject(new UserError("User cancelled"))}
        >
          Cancel
        </ButtonComponent>
        <ButtonComponent
          onClick={() => { resolve(); }}
        >
          {ctaLabel}
        </ButtonComponent>
      </ModalFooterPortal>
    </Modal>
  );
}
);

export const AllowanceManagementProvider = memo(({ children }: { children: ReactNode }) => {
  const [setAllowanceRequest, setSetAllowanceRequest] = useState<AllowanceResolver>();
  const [requireAllowanceRequest, setRequireAllowanceRequest] = useState<AllowanceResolver>();

  const value = useMemo<AllowanceContextType>(() => ({
    setAllowance: async (address, request, expires_at) => {
      return new Promise<void>((resolve, reject) => {
        setSetAllowanceRequest({
          address,
          request,
          expires_at,
          resolve: () => {
            setSetAllowanceRequest(undefined);
            resolve();
          },
          reject: (e) => {
            setSetAllowanceRequest(undefined);
            reject(e);
          }
        });
      });
    },
    requireAllowance: async (address, request, expires_at) => {
      return new Promise<void>((resolve, reject) => {
        setRequireAllowanceRequest({
          address,
          request,
          expires_at,
          resolve: () => {
            setRequireAllowanceRequest(undefined);
            resolve();
          },
          reject: (e) => {
            setRequireAllowanceRequest(undefined);
            reject(e);
          }
        });
      });
    },
  }), []);

  return (
    <CurrencyAllowanceContext.Provider value={value}>
      {setAllowanceRequest && (
        <ApprovalModal
          {...setAllowanceRequest}
          type="update"
        />
      )}
      {requireAllowanceRequest && (
        <ApprovalModal
          {...requireAllowanceRequest}
          type="require"
        />
      )}
      {children}
    </CurrencyAllowanceContext.Provider>
  );
});
