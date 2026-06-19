import { Component, Inject, Input, OnInit } from '@angular/core';
import { AsyncPipe, NgIf } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog'
import { MatIconModule } from '@angular/material/icon';

import * as Mustache from 'mustache';
import { NgbDateStruct } from '@ng-bootstrap/ng-bootstrap';
import { Observable } from '@librairies/rxjs/internal/Observable';
import { TranslateModule, TranslateService } from '@ngx-translate/core';
import { catchError, map } from 'rxjs/operators';

import { I18nService } from '@geonature/shared/translate/i18n-service';
import { AuthService, User } from '@geonature/components/auth/auth.service';
import { ConfigService } from '@geonature/services/config.service';

export interface UserInfos {
  firstname: string;
  lastname: string;
}

export interface AccessRequestData {
  areas: string[];
  taxa: string[];
  sensitivity_filter: boolean | null;
  expiration_date: NgbDateStruct | null;
}

export interface AccessRequestInfos {
  areas: string;
  taxa: string;
  sensitiveAccess: boolean;
  endAccessDate: string;
}

export interface WebsiteInfos {
  name: string;
}

export interface DialogData {
  accessRequestData: AccessRequestData,
  customData: Object,
}

@Component({
  standalone: true,
  selector: 'permission-request-convention-dialog',
  templateUrl: './convention-dialog.component.html',
  styleUrls : ['./convention-dialog.component.scss'],
  imports: [AsyncPipe, NgIf, MatDialogModule, MatIconModule, MatButtonModule, TranslateModule],
})
export class ConventiondDialogContent implements OnInit {

  private defaultTplPath = 'modules/permrequests/assets/templates/convention.default.tpl.html';
  private customTplPath = 'modules/permrequests/assets/custom/templates/convention.tpl.html';
  private rawTemplate = '';

  accessRequestInfos?: AccessRequestInfos;
  conventionContent: Observable<string>;
  websiteInfos: WebsiteInfos;
  userInfos: UserInfos;

  constructor(
    @Inject(MAT_DIALOG_DATA) private data: DialogData,
    private authService: AuthService,
    private configService: ConfigService,
    private http: HttpClient,
    private i18nService: I18nService,
    private translateService: TranslateService
  ) {
    this.conventionContent = new Observable<string>();
    this.websiteInfos = { name: this.configService.appName };
    this.userInfos = this.buildUserInfos();
    this.i18nService.initializeModuleTranslateService(this.translateService);
  }

  ngOnInit(): void {
    this.accessRequestInfos = this.buildAccessRequestInfos();

    this.conventionContent = this.http
      .get(this.customTplPath, { responseType: 'text' })
      .pipe(
        catchError(() => this.http.get(this.defaultTplPath, { responseType: 'text' })),
        map((template) => {
          this.rawTemplate = template;
          return this.renderTemplate();
        })
      );
  }

  private renderTemplate() {
    const mustacheLib = (Mustache as any).default ?? Mustache;
    const rendered = mustacheLib.render(this.rawTemplate, {
      accessRequest: this.accessRequestInfos,
      customData: this.data.customData,
      user: this.userInfos,
      website: this.websiteInfos,
    });
    return rendered;
  }

  private buildUserInfos(): UserInfos {
    const currentUser: User = this.authService.getCurrentUser() as User;
    const userInfos: UserInfos = {
      firstname: currentUser.prenom_role ?? '',
      lastname: currentUser.nom_role ?? '',
    };
    return userInfos;
  }

  private buildAccessRequestInfos(): AccessRequestInfos {
    const accessRequestInfos: AccessRequestInfos = {
      areas: this.data.accessRequestData.areas.join(', '),
      taxa: this.data.accessRequestData.taxa.join(', '),
      sensitiveAccess: !!this.data.accessRequestData.sensitivity_filter,
      endAccessDate: this.formatDate(this.data.accessRequestData.expiration_date),
    };
    return accessRequestInfos;
  }

  private formatDate(date: NgbDateStruct | null): string {
    let formatedDate = '';
    if (date) {
      const day = this.padStartWithZero(date.day);
      const month = this.padStartWithZero(date.month);
      const year = date.year;
      formatedDate = `${day}/${month}/${year}`;
    }
    return formatedDate;
  }

  // TODO: replace by string.padStart() when we 'll use ES2017.
  private padStartWithZero(number: number, size = 2): string {
    let numberStr = number.toString();
    while (numberStr.length < size) {
      numberStr = '0' + numberStr;
    }
    return numberStr;
  }
}
