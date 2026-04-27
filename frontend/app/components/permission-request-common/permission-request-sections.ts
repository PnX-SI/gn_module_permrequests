export type PermissionRequestSectionMeta = {
  icon: string;
};

export const PERMISSION_REQUEST_SECTIONS: Record<
  'beneficiary' | 'description' | 'validity' | 'data',
  PermissionRequestSectionMeta
> = {
  beneficiary: {
    icon: 'person',
  },
  description: {
    icon: 'notes',
  },
  validity: {
    icon: 'event',
  },
  data: {
    icon: 'layers',
  },
};
