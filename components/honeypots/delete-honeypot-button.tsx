'use client';

interface DeleteHoneypotButtonProps {
  honeypot: {
    id: string;
    name: string;
  };
}

export default function DeleteHoneypotButton({
  honeypot,
}: DeleteHoneypotButtonProps) {
  const handleSoftDelete = async () => {
    if (
      !confirm(
        `Are you sure you want to decommission the honeypot "${honeypot.name}"? This will stop monitoring but preserve data.`
      )
    ) {
      return;
    }

    try {
      const response = await fetch(`/api/honeypots/${honeypot.id}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to decommission honeypot');
      }

      // Refresh the page to show updated list
      window.location.reload();
    } catch (error) {
      alert(
        `Failed to decommission honeypot: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  };

  const handleHardDelete = async () => {
    if (
      !confirm(
        `Are you sure you want to PERMANENTLY DELETE the honeypot "${honeypot.name}"? This action CANNOT be undone and will remove all data.`
      )
    ) {
      return;
    }

    try {
      const response = await fetch(`/api/honeypots/${honeypot.id}?hard=true`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete honeypot');
      }

      // Refresh the page to show updated list
      window.location.reload();
    } catch (error) {
      alert(
        `Failed to delete honeypot: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  };

  const handleDelete = () => {
    const choice = confirm(
      `Choose deletion type for "${honeypot.name}":\n\nOK = Soft Decommission (preserve data)\nCancel = Hard Delete (remove everything)`
    );
    if (choice) {
      handleSoftDelete();
    } else {
      handleHardDelete();
    }
  };

  return (
    <button
      onClick={handleDelete}
      className="text-error-600 dark:text-error-400 hover:text-error-900 dark:hover:text-error-100 mr-4"
      title="Delete honeypot"
    >
      🗑️
    </button>
  );
}
