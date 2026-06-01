'use client';

interface EnterpriseIntakeModalProps {
  isOpen: boolean;
  onClose: () => void;
  invoiceType: string;
  fixedEstimate?: number;
}

export function EnterpriseIntakeModal({
  isOpen,
  onClose,
}: EnterpriseIntakeModalProps) {
  if (!isOpen) return null;
  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={onClose}
    >
      <div
        className="rounded-xl bg-white p-8 shadow-2xl dark:bg-neutral-900"
        onClick={(e) => e.stopPropagation()}
      >
        <p className="text-lg font-semibold">Enterprise intake — coming soon.</p>
        <button
          className="mt-4 rounded bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
          onClick={onClose}
        >
          Close
        </button>
      </div>
    </div>
  );
}
