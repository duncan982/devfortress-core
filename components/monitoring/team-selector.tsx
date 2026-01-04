'use client';

import { useRouter } from 'next/navigation';

interface TeamSelectorProps {
  teamMemberships: Array<{
    teamId: string;
    team: {
      name: string;
    };
  }>;
  currentTeamId: string;
}

export function TeamSelector({ teamMemberships, currentTeamId }: TeamSelectorProps) {
  const router = useRouter();

  const handleTeamChange = (teamId: string) => {
    router.push(`/dashboard/monitoring?teamId=${teamId}`);
  };

  return (
    <div className="mt-4">
      <label
        htmlFor="team-select"
        className="block text-sm font-medium text-neutral-700 dark:text-neutral-300"
      >
        Select Team
      </label>
      <select
        id="team-select"
        value={currentTeamId}
        onChange={(e) => handleTeamChange(e.target.value)}
        className="mt-2 block rounded-lg border border-neutral-300 bg-white px-4 py-2 text-sm shadow-sm focus:border-primary-500 focus:ring-primary-500 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
      >
        {teamMemberships.map((member) => (
          <option key={member.teamId} value={member.teamId}>
            {member.team.name}
          </option>
        ))}
      </select>
    </div>
  );
}