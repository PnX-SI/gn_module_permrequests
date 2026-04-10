export type PermissionRequestSectionMeta = {
  title: string;
  icon: string;
  subtitle?: string | null;
};

export const PERMISSION_REQUEST_SECTIONS: Record<
  'beneficiary' | 'description' | 'validity' | 'data',
  PermissionRequestSectionMeta
> = {
  beneficiary: {
    title: 'Bénéficiaire',
    icon: 'person',
    subtitle: 'Auteur et portée de la demande.',
  },
  description: {
    title: 'Description',
    icon: 'notes',
  },
  validity: {
    title: 'Fenêtre de validité',
    icon: 'event',
    subtitle: 'Période pendant laquelle la permission est requise.',
  },
  data: {
    title: 'Données concernées',
    icon: 'layers',
    subtitle: 'Sélectionnez les taxons et zones concernés.',
  },
};
