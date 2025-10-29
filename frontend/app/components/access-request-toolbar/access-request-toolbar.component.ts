import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatDialog } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { Router } from '@angular/router';

import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { ConfirmationDialog } from '@geonature_common/others/modal-confirmation/confirmation.dialog';
import { ModuleService } from '@geonature/services/module.service';

import { AccessRequest } from '../../models/accessRequest';
import { AccessRequestService } from '../../services/accessRequest.service';
import { ROUTE_PATHS } from '../../gnModule.module';
@Component({
  standalone: true,
  selector: 'access-request-toolbar',
  templateUrl: 'access-request-toolbar.component.html',
  styleUrls: ['./access-request-toolbar.component.scss'],
  imports: [GN2CommonModule, CommonModule, RouterModule, MatButtonModule],
})
export class AccessRequestToolbarComponent {
  constructor(
    private _accessRequestService: AccessRequestService,
    private _dialog: MatDialog,
    private _moduleService: ModuleService,
    private _router: Router
  ) {}

  @Input()
  accessRequest: AccessRequest | null = null;

  @Input()
  withInfo: boolean = true;
  @Input()
  withEdit: boolean = true;
  @Input()
  withDelete: boolean = true;
  @Input()
  withValidate: boolean = true;

  @Output()
  deleted = new EventEmitter<number>();

  @Output()
  updated = new EventEmitter<number>();

  validationRequestPending = false;

  get currentValidationState(): 'true' | 'false' | null {
    if (this.accessRequest?.validated === true) {
      return 'true';
    }
    if (this.accessRequest?.validated === false) {
      return 'false';
    }
    return null;
  }

  get infoRouterLink(): string {
    if (!this.accessRequest) {
      return '';
    }
    return `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.accessRequest(this.accessRequest.id_access_request)}`;
  }

  get editRouterLink(): string {
    if (!this.accessRequest) {
      return '';
    }
    return `/${this._moduleService.currentModule.module_url}/${ROUTE_PATHS.accessRequest(this.accessRequest.id_access_request)}/edit`;
  }

  deleteAccessRequest() {
    if (!this.accessRequest) {
      return;
    }
    const message =
      "Vous vous apprétez à supprimer la requête d'accès #" +
      this.accessRequest.id_access_request +
      '\
      Voulez-vous continuer ? \
    ';
    const dialogRef = this._dialog.open(ConfirmationDialog, {
      width: 'auto',
      // position: { top: '5%' },
      data: { message: message, yesColor: 'basic', noColor: 'warn' },
    });
    dialogRef.afterClosed().subscribe((result: any) => {
      if (result && this.accessRequest) {
        this._accessRequestService.deleteAccessRequest(this.accessRequest).subscribe(() => {
          this.deleted.emit(this.accessRequest?.id_access_request);
        });
      }
    });
  }

  onValidationButtonClick(rawValue: 'true' | 'false'): void {
    if (!this.accessRequest || !this.accessRequest.cruved?.V) {
      return;
    }

    let nextValidatedValue: boolean | null;
    if (this.currentValidationState === rawValue) {
      nextValidatedValue = null;
    } else {
      nextValidatedValue = rawValue === 'true';
    }

    this.validationRequestPending = true;

    this._accessRequestService
      .updateValidated(this.accessRequest.id_access_request, { validated: nextValidatedValue })
      .subscribe({
        next: (updatedAccessRequest: AccessRequest) => {
          this.accessRequest = updatedAccessRequest;
          this.updated.emit(updatedAccessRequest.id_access_request);
        },
        error: () => {
          this.validationRequestPending = false;
        },
        complete: () => {
          this.validationRequestPending = false;
        },
      });
  }
}
