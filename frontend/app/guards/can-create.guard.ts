import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { ModuleService } from '@geonature/services/module.service';
import { CruvedStoreService } from '@geonature_common/service/cruved-store.service';
import { PermissionRequestService } from '../services/permissionRequest.service';

export const canCreateGuard: CanActivateFn = () => {
  const moduleService = inject(ModuleService);
  const cruvedStore = inject(CruvedStoreService);
  const router = inject(Router);
  const permissionRequestService = inject(PermissionRequestService);

  const currentModule = moduleService.currentModule;
  const canCreate = permissionRequestService.canCreate(
    cruvedStore.cruved?.[currentModule.module_code]
  );
  if (canCreate) {
    return true;
  }

  return router.createUrlTree(['/', currentModule.module_url]) as UrlTree;
};
