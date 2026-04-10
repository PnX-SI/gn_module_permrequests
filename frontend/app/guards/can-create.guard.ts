import { inject } from '@angular/core';
import { CanActivateFn, Router, UrlTree } from '@angular/router';
import { ModuleService } from '@geonature/services/module.service';
import { CruvedStoreService } from '@geonature_common/service/cruved-store.service';

export const canCreateGuard: CanActivateFn = () => {
  const moduleService = inject(ModuleService);
  const cruvedStore = inject(CruvedStoreService);
  const router = inject(Router);

  const currentModule = moduleService.currentModule;
  const canCreate = canCreatePermission(cruvedStore.cruved?.[currentModule.module_code]);
  if (canCreate) {
    return true;
  }

  return router.createUrlTree(['/', currentModule.module_url]) as UrlTree;
};

export function canCreatePermission(cruvedStoreForModule: any): boolean {
  // cruved is 0, 1, 2, 3
  // the creation is not really scoped: 0 forbidden, else is authorized
  const canCreateScope = cruvedStoreForModule?.cruved?.C ?? 0;
  return canCreateScope > 0;
}
