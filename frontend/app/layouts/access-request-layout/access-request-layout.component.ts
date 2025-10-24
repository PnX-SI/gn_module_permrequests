import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ModuleService } from '@geonature/services/module.service';

import { AccessRequestSummary } from '../../models/accessRequestSummary';
import { ModuleLayoutComponent } from '../module-layout/module-layout.component';

@Component({
  standalone: true,
  selector: 'access-request-layout',
  templateUrl: 'access-request-layout.component.html',
  styleUrls: ['access-request-layout.component.scss'],
  imports: [RouterModule, CommonModule, ModuleLayoutComponent],
})
export class AccessRequestLayoutComponent {
  get homeRouterLink(): string {
    return `/${this._modules.currentModule.module_url}`;
  }

  @Input()
  accessRequestSummary!: AccessRequestSummary;

  constructor(private _modules: ModuleService) {}
}
